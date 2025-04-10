from fastapi import FastAPI, UploadFile, File, BackgroundTasks, HTTPException
import httpx
import os
import shutil
import time
from typing import Dict, Any
import uuid
from pydantic import BaseModel

from utils.logger import setup_logger

# Set up logger
logger = setup_logger(__name__, log_file="/var/log/pii-guardian/api.log")

app = FastAPI(title="PII Guardian API")

PROCESSOR_SERVICE_URL = os.environ.get("PROCESSOR_SERVICE_URL", "http://processor:8001")
UPLOAD_DIR = os.environ.get("UPLOAD_DIR", "/tmp/pii-guardian")

# Ensure upload directory exists
os.makedirs(UPLOAD_DIR, exist_ok=True)

class TransformRequest(BaseModel):
    methods: str = "regex,international"
    countries: str = "US,AR"
    transformation_method: str = "pseudonymize"

@app.get("/")
async def read_root():
    return {"status": "ok", "service": "PII Guardian API Gateway"}

@app.get("/health")
async def health_check():
    # Check processor service
    processor_status = "unknown"
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            response = await client.get(f"{PROCESSOR_SERVICE_URL}/health")
            if response.status_code == 200:
                processor_status = "ok"
            else:
                processor_status = f"error: status {response.status_code}"
    except Exception as e:
        processor_status = f"error: {str(e)}"
    
    return {
        "status": "ok",
        "service": "API Gateway",
        "dependencies": {
            "processor": processor_status
        },
        "timestamp": time.time()
    }

@app.post("/api/v1/detect")
async def detect_pii(
    background_tasks: BackgroundTasks, 
    file: UploadFile = File(...),
    methods: str = "regex,gliner,presidio,llm_semantic,quantum_classification,international",
    countries: str = "US,AR"
):
    """Detect PII in an uploaded file"""
    job_id = str(uuid.uuid4())
    logger.info(f"Submitting job {job_id} for PII detection")
    
    # Save file temporarily
    file_location = os.path.join(UPLOAD_DIR, f"{job_id}_{file.filename}")
    try:
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(file.file, file_object)
    except Exception as e:
        logger.error(f"Error saving file: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing uploaded file: {str(e)}")
    finally:
        file.file.close()
    
    # Submit job to processor service
    background_tasks.add_task(
        submit_job, 
        job_id, 
        file_location, 
        methods, 
        countries
    )
    
    return {"job_id": job_id, "status": "submitted"}

@app.post("/api/v1/transform")
async def transform_pii(
    background_tasks: BackgroundTasks, 
    file: UploadFile = File(...),
    transform_params: TransformRequest = None
):
    """Detect and transform PII in an uploaded file"""
    if transform_params is None:
        transform_params = TransformRequest()
    
    job_id = str(uuid.uuid4())
    logger.info(f"Submitting job {job_id} for PII transformation")
    
    # Save file temporarily
    file_location = os.path.join(UPLOAD_DIR, f"{job_id}_{file.filename}")
    try:
        with open(file_location, "wb+") as file_object:
            shutil.copyfileobj(file.file, file_object)
    except Exception as e:
        logger.error(f"Error saving file: {e}")
        raise HTTPException(status_code=500, detail=f"Error processing uploaded file: {str(e)}")
    finally:
        file.file.close()
    
    # Submit job to processor service with transformation
    background_tasks.add_task(
        submit_transform_job, 
        job_id, 
        file_location, 
        transform_params.methods,
        transform_params.countries,
        transform_params.transformation_method
    )
    
    return {"job_id": job_id, "status": "submitted"}

@app.get("/api/v1/jobs/{job_id}")
async def get_job_status(job_id: str):
    """Get the status of a submitted job"""
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{PROCESSOR_SERVICE_URL}/jobs/{job_id}")
            return response.json()
    except Exception as e:
        logger.error(f"Error getting job status: {e}")
        raise HTTPException(status_code=500, detail=f"Error retrieving job status: {str(e)}")

async def submit_job(job_id: str, file_path: str, methods: str, countries: str):
    """Submit a PII detection job to the processor service"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            with open(file_path, "rb") as f:
                files = {"file": f}
                data = {
                    "job_id": job_id,
                    "methods": methods,
                    "countries": countries
                }
                response = await client.post(
                    f"{PROCESSOR_SERVICE_URL}/submit", 
                    files=files, 
                    data=data
                )
                
                if response.status_code != 200:
                    logger.error(f"Error submitting job: {response.text}")
    except Exception as e:
        logger.error(f"Error submitting job: {e}")
    finally:
        # Clean up the file
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            logger.error(f"Error removing temporary file: {e}")

async def submit_transform_job(job_id: str, file_path: str, methods: str, countries: str, transform_method: str):
    """Submit a PII transformation job to the processor service"""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            with open(file_path, "rb") as f:
                files = {"file": f}
                data = {
                    "job_id": job_id,
                    "methods": methods,
                    "countries": countries,
                    "transform_method": transform_method
                }
                response = await client.post(
                    f"{PROCESSOR_SERVICE_URL}/submit_transform", 
                    files=files, 
                    data=data
                )
                
                if response.status_code != 200:
                    logger.error(f"Error submitting job: {response.text}")
    except Exception as e:
        logger.error(f"Error submitting job: {e}")
    finally:
        # Clean up the file
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
        except Exception as e:
            logger.error(f"Error removing temporary file: {e}")
