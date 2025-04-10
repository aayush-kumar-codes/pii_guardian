import json
import os
import pika
import time
import traceback
from typing import Dict, Any, List

from utils.logger import setup_logger
from utils.regex_patterns import PIIRegexPatterns
from utils.international_patterns import InternationalPIIPatterns

# Set up logger
logger = setup_logger(__name__, log_file="/var/log/pii-guardian/regex.log")

RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://rabbitmq:5672")

def detect_with_regex(text: str, countries: List[str]) -> Dict[str, Any]:
    """Detect PII using regex patterns"""
    results = []
    
    # Get standard patterns
    regex_patterns = PIIRegexPatterns.get_all_patterns()
    
    # Apply each pattern
    for pii_type, pattern in regex_patterns.items():
        matches = pattern.findall(text)
        if matches:
            # Ensure matches are strings
            string_matches = [str(match) for match in matches]
            results.append({
                'type': pii_type,
                'matches': string_matches,
                'detection_method': 'regex'
            })
    
    # Apply international patterns if requested
    if any(country in countries for country in ['AR', 'ARG', 'ARGENTINA']):
        argentina_matches = InternationalPIIPatterns.detect_argentina_pii(text)
        results.extend(argentina_matches)
    
    return {
        'pii_matches': results,
        'pii_detected': len(results) > 0
    }

def callback(ch, method, properties, body):
    """Process incoming messages from RabbitMQ"""
    try:
        message = json.loads(body)
        
        # Extract data
        job_id = message.get('job_id')
        text = message.get('text')
        chunk_idx = message.get('chunk_idx', 0)
        total_chunks = message.get('total_chunks', 1)
        countries = message.get('countries', 'US').split(',')
        
        logger.info(f"Processing job {job_id} chunk {chunk_idx+1}/{total_chunks} with regex detector")
        
        # Process text with regex
        results = detect_with_regex(text, countries)
        
        # Send results to aggregator
        connection_out = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
        channel_out = connection_out.channel()
        channel_out.queue_declare(queue='aggregator_tasks')
        
        # Create response message
        response = {
            'job_id': job_id,
            'service': 'regex',
            'action': 'results',
            'chunk_idx': chunk_idx,
            'total_chunks': total_chunks,
            'results': results
        }
        
        # Send message
        channel_out.basic_publish(
            exchange='',
            routing_key='aggregator_tasks',
            body=json.dumps(response)
        )
        
        connection_out.close()
        
        logger.info(f"Job {job_id} chunk {chunk_idx+1}/{total_chunks} completed with {len(results['pii_matches'])} matches")
        
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
        channel.queue_declare(queue='regex_tasks')
        
        # Configure consumer
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(queue='regex_tasks', on_message_callback=callback)
        
        logger.info("Regex Service started, waiting for messages...")
        
        # Start consuming
        channel.start_consuming()
    except Exception as e:
        logger.error(f"Critical error in regex service: {e}", exc_info=True)
        time.sleep(5)  # Wait before restarting
        main()  # Restart the service

if __name__ == "__main__":
    # Wait for RabbitMQ to be ready
    time.sleep(10)
    main()
