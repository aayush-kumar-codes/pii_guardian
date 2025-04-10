import json
import os
import pika
import time
from typing import Dict, Any

from utils.logger import setup_logger
from services.transformation_service import DataTransformationService

# Set up logger
logger = setup_logger(__name__, log_file="/var/log/pii-guardian/transformation.log")

RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://rabbitmq:5672")

# Initialize transformation service
transformer = DataTransformationService()

def transform_data(text: str, detection_results: Dict[str, Any], method: str = 'pseudonymize') -> str:
    """Transform text to anonymize PII"""
    # Set transformation method
    transformer.set_transformation_method(method)
    
    # Transform text
    return transformer.transform_data(text, detection_results)

def callback(ch, method, properties, body):
    """Process incoming messages from RabbitMQ"""
    try:
        message = json.loads(body)
        
        # Extract data
        job_id = message.get('job_id')
        text = message.get('text')
        detection_results = message.get('detection_results')
        transform_method = message.get('transform_method', 'pseudonymize')
        
        logger.info(f"Processing job {job_id} with transformation service")
        
        # Transform text
        transformed_text = transform_data(text, detection_results, transform_method)
        
        # Generate transformation report
        report = transformer.generate_transformation_report(
            text, 
            transformed_text, 
            detection_results
        )
        
        # Send results back
        connection_out = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
        channel_out = connection_out.channel()
        channel_out.queue_declare(queue='processor_results')
        
        # Create response message
        response = {
            'job_id': job_id,
            'transformed_text': transformed_text,
            'detection_results': detection_results,
            'transformation_report': report
        }
        
        # Send message
        channel_out.basic_publish(
            exchange='',
            routing_key='processor_results',
            body=json.dumps(response)
        )
        
        connection_out.close()
        logger.info(f"Job {job_id} transformation complete: {report['total_pii_instances']} instances transformed")
        
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
        channel.queue_declare(queue='transformation_tasks')
        
        # Configure consumer
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(queue='transformation_tasks', on_message_callback=callback)
        
        logger.info("Transformation Service started, waiting for messages...")
        
        # Start consuming
        channel.start_consuming()
    except Exception as e:
        logger.error(f"Critical error in transformation service: {e}", exc_info=True)
        time.sleep(5)  # Wait before restarting
        main()  # Restart the service

if __name__ == "__main__":
    # Wait for RabbitMQ to be ready
    time.sleep(10)
    main()
