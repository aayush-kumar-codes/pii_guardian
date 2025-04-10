import json
import os
import pika
import time
from typing import Dict, Any, List
import traceback

from utils.logger import setup_logger

# Set up logger
logger = setup_logger(__name__, log_file="/var/log/pii-guardian/aggregator.log")

RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://rabbitmq:5672")

# Store results for each job
job_results = {}
job_texts = {}

def combine_detection_results(
    regex_results: List[Dict[str, Any]] = None,
    llm_results: List[Dict[str, Any]] = None,
    presidio_results: List[Dict[str, Any]] = None,
    ner_results: List[Dict[str, Any]] = None,
    gliner_results: List[Dict[str, Any]] = None,
    quantum_results: Dict[str, Any] = None
) -> Dict[str, Any]:
    """Combine results from different detection methods"""
    all_matches = []
    
    # Add results from each method
    if regex_results:
        all_matches.extend(regex_results)
    if llm_results:
        all_matches.extend(llm_results)
    if presidio_results:
        all_matches.extend(presidio_results)
    if ner_results:
        all_matches.extend(ner_results)
    if gliner_results:
        all_matches.extend(gliner_results)
    
    # Deduplicate matches
    seen_matches = set()
    unique_matches = []
    
    for match in all_matches:
        # Extract match key for deduplication
        match_type = match.get('type', '')
        match_value = match.get('matches', [])
        if isinstance(match_value, list):
            match_value = tuple(sorted([str(m) for m in match_value]))
        else:
            match_value = str(match_value)
            
        match_tuple = (match_type, match_value)
        
        if match_tuple not in seen_matches:
            seen_matches.add(match_tuple)
            unique_matches.append(match)
    
    # Compute confidence scores
    method_counts = {}
    method_confidence = {}
    
    for match in unique_matches:
        method = match.get('detection_method', 'unknown')
        method_counts[method] = method_counts.get(method, 0) + 1
        
        # Track average confidence per method
        confidence = match.get('confidence', 0.5)
        if method not in method_confidence:
            method_confidence[method] = []
        method_confidence[method].append(confidence)
    
    # Calculate average confidence per method
    avg_confidence = {}
    for method, confidences in method_confidence.items():
        avg_confidence[method] = sum(confidences) / len(confidences)
    
    # Normalize method counts by total matches
    total_matches = sum(method_counts.values()) or 1
    normalized_scores = {
        method: count / total_matches
        for method, count in method_counts.items()
    }
    
    # Add quantum confidence
    if quantum_results:
        normalized_scores['quantum'] = quantum_results.get('pii_probability', 0)
    
    # Combine normalized scores with confidence scores
    final_scores = {}
    for method in set(normalized_scores.keys()) | set(avg_confidence.keys()):
        count_weight = normalized_scores.get(method, 0)
        conf_weight = avg_confidence.get(method, 0.5)
        final_scores[method] = (count_weight + conf_weight) / 2
    
    return {
        'pii_matches': unique_matches,
        'pii_detected': len(unique_matches) > 0,
        'confidence_scores': final_scores,
        'quantum_analysis': quantum_results
    }

def check_job_complete(job_id: str) -> bool:
    """Check if all chunks for a job have been processed"""
    # If job not in results, it's not complete
    if job_id not in job_results:
        return False
    
    # Get expected total chunks
    total_chunks = job_results[job_id].get('total_chunks', 1)
    
    # Check if we have regex results for all chunks
    regex_chunks = len(job_results[job_id].get('regex', {}))
    
    # Check if we have ML results for all chunks
    ml_chunks = len(job_results[job_id].get('ml', {}))
    
    # Get methods used
    methods = job_results[job_id].get('methods', ['regex'])
    
    # Determine if all expected services have reported for all chunks
    ml_methods = ['llm_semantic', 'quantum_classification', 'presidio', 'ner', 'gliner']
    regex_methods = ['regex', 'international']
    
    needs_regex = any(method in regex_methods for method in methods)
    needs_ml = any(method in ml_methods for method in methods)
    
    if needs_regex and regex_chunks < total_chunks:
        return False
    
    if needs_ml and ml_chunks < total_chunks:
        return False
    
    # Check if we have text for all chunks
    if len(job_texts.get(job_id, {})) < total_chunks:
        return False
    
    return True

def process_completed_job(job_id: str):
    """Process a completed job by combining results and sending for transformation"""
    logger.info(f"Processing completed job {job_id}")
    
    try:
        # Combine text from all chunks
        text = ""
        for i in range(job_results[job_id].get('total_chunks', 1)):
            text += job_texts[job_id].get(i, "")
        
        # Combine results from all chunks
        combined_regex_results = []
        combined_llm_results = []
        combined_presidio_results = []
        combined_ner_results = []
        combined_gliner_results = []
        quantum_results = None
        
        # Process regex results
        for chunk_idx, chunk_results in job_results[job_id].get('regex', {}).items():
            combined_regex_results.extend(chunk_results.get('pii_matches', []))
        
        # Process ML results
        for chunk_idx, chunk_results in job_results[job_id].get('ml', {}).items():
            # Extract LLM semantic results
            if 'results' in chunk_results:
                # LLM semantic results
                if 'llm_semantic' in chunk_results['results']:
                    llm_semantic = chunk_results['results']['llm_semantic']
                    if isinstance(llm_semantic, list):
                        combined_llm_results.extend(llm_semantic)
                
                # Presidio results
                if 'presidio' in chunk_results['results']:
                    presidio_results = chunk_results['results']['presidio']
                    if isinstance(presidio_results, list):
                        combined_presidio_results.extend(presidio_results)
                
                # NER results
                if 'ner' in chunk_results['results']:
                    ner_results = chunk_results['results']['ner']
                    if isinstance(ner_results, list):
                        combined_ner_results.extend(ner_results)
                
                # GLiNER results
                if 'gliner' in chunk_results['results']:
                    gliner_results = chunk_results['results']['gliner']
                    if isinstance(gliner_results, list):
                        combined_gliner_results.extend(gliner_results)
                
                # Use the quantum result from the first chunk
                if chunk_idx == '0' and 'quantum' in chunk_results['results']:
                    quantum_results = chunk_results['results']['quantum']
        
        # Combine all results
        combined_results = combine_detection_results(
            regex_results=combined_regex_results,
            llm_results=combined_llm_results,
            presidio_results=combined_presidio_results,
            ner_results=combined_ner_results,
            gliner_results=combined_gliner_results,
            quantum_results=quantum_results
        )
        
        # Check if transformation is requested
        transform_method = job_results[job_id].get('transform_method')
        
        if transform_method:
            # Send to transformation service
            connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
            channel = connection.channel()
            channel.queue_declare(queue='transformation_tasks')
            
            # Create transformation message
            transform_message = {
                'job_id': job_id,
                'text': text,
                'detection_results': combined_results,
                'transform_method': transform_method
            }
            
            # Send message
            channel.basic_publish(
                exchange='',
                routing_key='transformation_tasks',
                body=json.dumps(transform_message)
            )
            
            connection.close()
            logger.info(f"Job {job_id} sent for transformation")
        else:
            # Send results back to processor
            connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
            channel = connection.channel()
            channel.queue_declare(queue='processor_results')
            
            # Create results message
            results_message = {
                'job_id': job_id,
                'detection_results': combined_results
            }
            
            # Send message
            channel.basic_publish(
                exchange='',
                routing_key='processor_results',
                body=json.dumps(results_message)
            )
            
            connection.close()
            logger.info(f"Job {job_id} results sent to processor")
        
    except Exception as e:
        logger.error(f"Error processing completed job {job_id}: {e}", exc_info=True)

def callback(ch, method, properties, body):
    """Process incoming messages from RabbitMQ"""
    try:
        message = json.loads(body)
        
        # Extract data
        job_id = message.get('job_id')
        service = message.get('service')
        action = message.get('action', 'results')
        
        if not job_id:
            logger.warning(f"Received message without job_id: {message}")
            ch.basic_ack(delivery_tag=method.delivery_tag)
            return
        
        # Initialize job results if needed
        if job_id not in job_results:
            job_results[job_id] = {'regex': {}, 'ml': {}}
        
        # Store original text if provided
        if action == 'store_text':
            chunk_idx = message.get('chunk_idx', 0)
            text = message.get('text', '')
            total_chunks = message.get('total_chunks', 1)
            transform_method = message.get('transform_method')
            
            # Initialize texts dict if needed
            if job_id not in job_texts:
                job_texts[job_id] = {}
            
            # Store text
            job_texts[job_id][chunk_idx] = text
            
            # Store job metadata
            job_results[job_id]['total_chunks'] = total_chunks
            if transform_method:
                job_results[job_id]['transform_method'] = transform_method
            
            logger.info(f"Stored text for job {job_id} chunk {chunk_idx+1}/{total_chunks}")
        
        # Store detection results
        elif action == 'results':
            chunk_idx = str(message.get('chunk_idx', 0))
            results = message.get('results', {})
            total_chunks = message.get('total_chunks', 1)
            
            # Store results
            if service == 'regex':
                job_results[job_id]['regex'][chunk_idx] = results
                logger.info(f"Stored regex results for job {job_id} chunk {int(chunk_idx)+1}/{total_chunks}")
            elif service == 'ml':
                job_results[job_id]['ml'][chunk_idx] = results
                job_results[job_id]['methods'] = results.get('detection_methods', [])
                logger.info(f"Stored ML results for job {job_id} chunk {int(chunk_idx)+1}/{total_chunks}")
            
            # Update job metadata
            job_results[job_id]['total_chunks'] = total_chunks
        
        # Check if job is complete
        if check_job_complete(job_id):
            logger.info(f"Job {job_id} is complete, processing results")
            process_completed_job(job_id)
            
    except Exception as e:
        logger.error(f"Error processing message: {e}", exc_info=True)
        logger.error(f"Message body: {body}")
    finally:
        # Acknowledge message
        ch.basic_ack(delivery_tag=method.delivery_tag)

def main():
    try:
        # Connect to RabbitMQ
        connection = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
        channel = connection.channel()
        
        # Declare queue
        channel.queue_declare(queue='aggregator_tasks')
        
        # Configure consumer
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(queue='aggregator_tasks', on_message_callback=callback)
        
        logger.info("Aggregator Service started, waiting for messages...")
        
        # Start consuming
        channel.start_consuming()
    except Exception as e:
        logger.error(f"Critical error in aggregator service: {e}", exc_info=True)
        time.sleep(5)  # Wait before restarting
        main()  # Restart the service

if __name__ == "__main__":
    # Wait for RabbitMQ to be ready
    time.sleep(10)
    main()
