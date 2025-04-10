import os
import json
import time
import shutil
import pika
import uuid
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
import httpx
from typing import Dict, Any, List, Optional
from pydantic import BaseModel

from utils.logger import setup_logger

# Set up logger
logger = setup_logger(__name__, log_file="/var/log/pii-guardian/processor.log")

app = FastAPI(title="PII Guardian Processor")

# Service URLs
REGEX_SERVICE_URL = os.environ.get("REGEX_SERVICE_URL", "http://regex:8002")
ML_SERVICE_URL = os.environ.get("ML_SERVICE_URL", "http://ml-models:8003")
TRANSFORMATION_SERVICE_URL = os.environ.get("TRANSFORMATION_SERVICE_URL", "http://transformation:8004")
AGGREGATOR_SERVICE_URL = os.environ.get("AGGREGATOR_SERVICE_URL", "http://aggregator:8005")
RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://rabbitmq:5672")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/tmp/pii-guardian")

# Ensure upload directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

# Track job status
job_status = {}

class ChunkingConfig(BaseModel):
    chunk_size: int = 100000
    overlap: int = 1000

@app.get("/")
def read_root():
    return {"status": "ok", "service": "PII Guardian Processor"}

@app.get("/health")
async def health_check():
    # Check RabbitMQ connection
    rabbitmq_status = "unknown"
    try:
        connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
        connection.close()
        rabbitmq_status = "ok"
    except Exception as e:
        rabbitmq_status = f"error: {str(e)}"
    
    return {
        "status": "ok",
        "service": "Document Processor",
        "dependencies": {
            "rabbitmq": rabbitmq_status
        },
        "timestamp": time.time()
    }

@app.post("/submit")
async def submit_job(
    file: UploadFile = File(...),
    job_id: str = Form(...),
    methods: str = Form("regex"),
    countries: str = Form("US,AR")
):
    """Submit a PII detection job"""
    # Save file
    file_location = os.path.join(UPLOAD_DIR, f"{job_id}_{file.filename}")
    try:
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(file.file, file_object)
    except Exception as e:
        logger.error(f"Error saving file: {e}")
        raise HTTPException(status_code=500, detail=f"Error saving file: {str(e)}")
    finally:
        file.file.close()
    
    # Update job status
    job_status[job_id] = {
        "status": "processing",
        "file": file.filename,
        "methods": methods,
        "countries": countries,
        "progress": 0,
        "start_time": time.time(),
        "transform_method": None
    }
    
    logger.info(f"Job {job_id} submitted for processing")
    
    # Process the document
    await process_document(job_id, file_location, methods, countries)
    
    return {"job_id": job_id, "status": "processing"}

@app.post("/submit_transform")
async def submit_transform_job(
    file: UploadFile = File(...),
    job_id: str = Form(...),
    methods: str = Form("regex"),
    countries: str = Form("US,AR"),
    transform_method: str = Form("pseudonymize")
):
    """Submit a PII detection and transformation job"""
    # Save file
    file_location = os.path.join(UPLOAD_DIR, f"{job_id}_{file.filename}")
    try:
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(file.file, file_object)
    except Exception as e:
        logger.error(f"Error saving file: {e}")
        raise HTTPException(status_code=500, detail=f"Error saving file: {str(e)}")
    finally:
        file.file.close()
    
    # Update job status
    job_status[job_id] = {
        "status": "processing",
        "file": file.filename,
        "methods": methods,
        "countries": countries,
        "progress": 0,
        "start_time": time.time(),
        "transform_method": transform_method
    }
    
    logger.info(f"Job {job_id} submitted for processing and transformation")
    
    # Process the document
    await process_document(job_id, file_location, methods, countries)
    
    return {"job_id": job_id, "status": "processing"}

@app.get("/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Get the status of a job"""
    if job_id not in job_status:
        raise HTTPException(status_code=404, detail="Job not found")
    
    status_copy = dict(job_status[job_id])
    
    # Add duration if job is not completed
    if status_copy["status"] not in ["completed", "failed"]:
        status_copy["duration"] = time.time() - status_copy["start_time"]
    
    # Remove internal fields
    if "start_time" in status_copy:
        del status_copy["start_time"]
    
    return status_copy

@app.delete("/jobs/{job_id}")
async def delete_job(job_id: str):
    """Delete a job and its associated data"""
    if job_id not in job_status:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Remove job status
    del job_status[job_id]
    
    # Clean up any job files
    job_files = [f for f in os.listdir(UPLOAD_DIR) if f.startswith(f"{job_id}_")]
    for file in job_files:
        try:
            os.remove(os.path.join(UPLOAD_DIR, file))
        except Exception as e:
            logger.error(f"Error removing file {file}: {e}")
    
    return {"status": "deleted"}

async def process_document(job_id: str, file_path: str, methods: str, countries: str):
    """Process a document by breaking it into chunks and sending to appropriate services"""
    from processor.chunking import chunk_document, get_file_size
    
    try:
        # Check file size
        file_size = get_file_size(file_path)
        chunk_size = 100000  # 100KB chunks
        
        # Update job status with file size
        job_status[job_id]["file_size"] = file_size
        
        # For small files, process in one go
        if file_size < chunk_size:
            logger.info(f"Processing small file ({file_size} bytes) as a single chunk")
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                text = f.read()
            
            # Process the text
            await process_chunk(job_id, text, 0, 1, methods, countries)
            
            # Update status
            job_status[job_id]["progress"] = 50
            job_status[job_id]["status"] = "aggregating"
            return
        
        # For larger files, process in chunks
        chunks = chunk_document(file_path, chunk_size)
        total_chunks = len(chunks)
        
        logger.info(f"Processing file in {total_chunks} chunks")
        
        # Update job status
        job_status[job_id]["total_chunks"] = total_chunks
        job_status[job_id]["processed_chunks"] = 0
        
        # Process each chunk
        for i, chunk in enumerate(chunks):
            logger.info(f"Processing chunk {i+1}/{total_chunks}")
            await process_chunk(job_id, chunk, i, total_chunks, methods, countries)
            
            # Update progress
            job_status[job_id]["processed_chunks"] += 1
            job_status[job_id]["progress"] = int((job_status[job_id]["processed_chunks"] / total_chunks) * 50)
        
        # Update status to aggregating
        job_status[job_id]["status"] = "aggregating"
        job_status[job_id]["progress"] = 50
    except Exception as e:
        logger.error(f"Error processing document: {e}", exc_info=True)
        job_status[job_id]["status"] = "failed"
        job_status[job_id]["error"] = str(e)
    finally:
        # Clean up
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            logger.error(f"Error cleaning up file: {e}")

async def process_chunk(job_id: str, text: str, chunk_idx: int, total_chunks: int, methods: str, countries: str):
    """Process a single document chunk"""
    try:
        method_list = methods.split(",")
        
        # Connect to RabbitMQ
        connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
        
        # Store original text in aggregator for later use
        channel = connection.channel()
        channel.queue

        # Create message
        original_text_message = {
            "job_id": job_id,
            "service": "processor",
            "action": "store_text",
            "chunk_idx": chunk_idx,
            "total_chunks": total_chunks,
            "text": text,
            "transform_method": job_status[job_id].get("transform_method")
        }
        
        # Send message
        channel.basic_publish(
            exchange='',
            routing_key='aggregator_tasks',
            body=json.dumps(original_text_message)
        )
        
        # Send to regex service if needed
        if "regex" in method_list or "international" in method_list:
            channel = connection.channel()
            channel.queue_declare(queue='regex_tasks')
            
            # Create message
            regex_message = {
                "job_id": job_id,
                "text": text,
                "chunk_idx": chunk_idx,
                "total_chunks": total_chunks,
                "methods": methods,
                "countries": countries
            }
            
            # Send message
            channel.basic_publish(
                exchange='',
                routing_key='regex_tasks',
                body=json.dumps(regex_message)
            )
            logger.info(f"Sent chunk {chunk_idx+1}/{total_chunks} to regex service")
        
        # Send to ML service if needed
        if "llm_semantic" in method_list or "quantum_classification" in method_list:
            channel = connection.channel()
            channel.queue_declare(queue='ml_tasks')
            
            # Create message
            ml_message = {
                "job_id": job_id,
                "text": text,
                "chunk_idx": chunk_idx,
                "total_chunks": total_chunks,
                "methods": methods
            }
            
            # Send message
            channel.basic_publish(
                exchange='',
                routing_key='ml_tasks',
                body=json.dumps(ml_message)
            )
            logger.info(f"Sent chunk {chunk_idx+1}/{total_chunks} to ML service")
        
        connection.close()
        
    except Exception as e:
        logger.error(f"Error processing chunk {chunk_idx}: {e}", exc_info=True)
        raise
