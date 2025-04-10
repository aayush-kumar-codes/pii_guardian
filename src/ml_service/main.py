import json
import os
import pika
import time
import torch
from typing import Dict, Any, List
import traceback

from utils.logger import setup_logger
from utils.presidio_integration import detect_with_presidio, init_presidio_analyzer
from utils.entity_recognition import detect_with_ner, load_ner_model, load_model

# Set up logger
logger = setup_logger(__name__, log_file="/var/log/pii-guardian/ml.log")

RABBITMQ_URL = os.environ.get("RABBITMQ_URL", "amqp://rabbitmq:5672")
DEVICE = os.environ.get("DEVICE", "cpu")  # 'cuda' for GPU support

# Import models - use try/except to handle potential import errors
try:
    from models.llm_classifier import LLMPIIClassifier
    from models.quantum_classifier import QuantumInspiredClassifier
    
    # Initialize models
    llm_classifier = LLMPIIClassifier(device=DEVICE)
    quantum_classifier = QuantumInspiredClassifier(input_dim=100, num_classes=10, complexity_level=0.5)
    
    # Initialize NER and Presidio models
    try:
        ner_model = load_ner_model()
        gliner_model = load_model()
        presidio_analyzer = init_presidio_analyzer(languages=["en"])
        logger.info("NER and Presidio models initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing NER/Presidio models: {e}", exc_info=True)
        ner_model = None
        gliner_model = None
        presidio_analyzer = None
    
    logger.info("All models initialized successfully")
except Exception as e:
    logger.error(f"Error initializing models: {e}", exc_info=True)
    # Create mock models for testing
    class MockLLMClassifier:
        def detect_pii(self, text: str) -> List[Dict[str, Any]]:
            return []
        
        def _generate_embedding(self, text: str) -> torch.Tensor:
            return torch.zeros((1, 100))
    
    class MockQuantumClassifier:
        def __call__(self, x: torch.Tensor) -> torch.Tensor:
            return torch.zeros((1, 10))
        
        def compute_uncertainty(self, probs: torch.Tensor) -> Dict[str, float]:
            return {"shannon_entropy": 0.0, "uncertainty_principle": 0.5, "probabilistic_variance": 0.0}
    
    llm_classifier = MockLLMClassifier()
    quantum_classifier = MockQuantumClassifier()
    ner_model = None
    gliner_model = None
    presidio_analyzer = None
    logger.warning("Using mock models due to initialization error")

def detect_with_llm(text: str) -> List[Dict[str, Any]]:
    """Detect PII using LLM-based semantic approach"""
    try:
        return llm_classifier.detect_pii(text)
    except Exception as e:
        logger.error(f"Error in LLM detection: {e}", exc_info=True)
        return []

def detect_with_quantum(text: str) -> Dict[str, Any]:
    """Detect PII using quantum-inspired classifier"""
    try:
        # Generate embedding from text
        embedding = llm_classifier._generate_embedding(text)
        
        # Prepare input for quantum classifier
        features = embedding.view(-1)[:100]  # Truncate/pad to 100 dim
        
        with torch.no_grad():
            outputs = quantum_classifier(features.unsqueeze(0))
            probabilities = torch.softmax(outputs, dim=1).squeeze(0)
            
            # Get uncertainty metrics
            uncertainty = quantum_classifier.compute_uncertainty(probabilities)
            
            # Get classification results
            _, predicted_class = torch.max(probabilities, 0)
            
            return {
                'pii_probability': probabilities[0].item(),  # Probability of being PII
                'predicted_class': predicted_class.item(),
                'uncertainty': uncertainty,
                'detection_method': 'quantum_classification'
            }
    except Exception as e:
        logger.error(f"Error in quantum detection: {e}", exc_info=True)
        return {
            'pii_probability': 0.0,
            'predicted_class': 0,
            'uncertainty': {'shannon_entropy': 0.0, 'uncertainty_principle': 0.0, 'probabilistic_variance': 0.0},
            'detection_method': 'quantum_classification'
        }

def detect_with_presidio_ml(text: str) -> List[Dict[str, Any]]:
    """Detect PII using Microsoft Presidio"""
    if presidio_analyzer is None:
        return []
    
    try:
        entities = [
            "PERSON", 
            "EMAIL_ADDRESS", 
            "PHONE_NUMBER", 
            "US_SSN",
            "CREDIT_CARD",
            "IBAN_CODE", 
            "PASSPORT",
            "DRIVER_LICENSE",
            "US_BANK_ACCOUNT",
            "US_ITIN",
            "IP_ADDRESS"
        ]
        
        return detect_with_presidio(text, presidio_analyzer, entities)
    except Exception as e:
        logger.error(f"Error in Presidio detection: {e}", exc_info=True)
        return []

def detect_with_ner_ml(text: str) -> List[Dict[str, Any]]:
    """Detect PII using Named Entity Recognition"""
    if ner_model is None:
        return []
    
    try:
        entity_mapping = {
            "PERSON": "person_name",
            "ORG": "organization",
            "GPE": "location",
            "LOC": "location",
            "MONEY": "financial",
            "CARDINAL": "number",
            "DATE": "date"
        }
        
        return detect_with_ner(text, ner_model, entity_mapping)
    except Exception as e:
        logger.error(f"Error in NER detection: {e}", exc_info=True)
        return []

def detect_with_gliner_ml(text: str) -> List[Dict[str, Any]]:
    """Detect PII using GLiNER-compatible interface"""
    if gliner_model is None:
        return []
    
    try:
        # Request entity types that are relevant for PII
        entities = ['PERSON', 'ORGANIZATION', 'LOCATION', 'FINANCIAL_INFO', 'NUMBER', 'DATE']
        gliner_results = gliner_model.predict(text, entities)
        
        # Convert to standard format
        results = []
        for entity in gliner_results:
            results.append({
                'type': entity['label'].lower(),
                'matches': [entity['text']],
                'detection_method': 'gliner',
                'confidence': 0.75,  # Default confidence
                'location': {'start': entity['start'], 'end': entity['end']}
            })
        
        return results
    except Exception as e:
        logger.error(f"Error in GLiNER detection: {e}", exc_info=True)
        return []

def callback(ch, method, properties, body):
    """Process incoming messages from RabbitMQ"""
    try:
        message = json.loads(body)
        
        # Extract data
        job_id = message.get('job_id')
        text = message.get('text')
        chunk_idx = message.get('chunk_idx', 0)
        total_chunks = message.get('total_chunks', 1)
        methods = message.get('methods', '').split(',')
        
        logger.info(f"Processing job {job_id} chunk {chunk_idx+1}/{total_chunks} with ML models")
        
        results = {'detection_methods': [], 'results': {}}
        
        # Process text with LLM if requested
        if 'llm_semantic' in methods:
            llm_results = detect_with_llm(text)
            results['results']['llm_semantic'] = llm_results
            results['detection_methods'].append('llm_semantic')
            logger.info(f"LLM detection complete: {len(llm_results)} matches")
        
        # Process text with quantum classifier if requested
        if 'quantum_classification' in methods:
            quantum_results = detect_with_quantum(text)
            results['results']['quantum'] = quantum_results
            results['detection_methods'].append('quantum_classification')
            logger.info(f"Quantum detection complete: probability {quantum_results['pii_probability']:.4f}")
        
        # Process with Presidio if requested
        if 'presidio' in methods and presidio_analyzer is not None:
            presidio_results = detect_with_presidio_ml(text)
            results['results']['presidio'] = presidio_results
            results['detection_methods'].append('presidio')
            logger.info(f"Presidio detection complete: {len(presidio_results)} matches")
        
        # Process with NER if requested
        if 'ner' in methods and ner_model is not None:
            ner_results = detect_with_ner_ml(text)
            results['results']['ner'] = ner_results
            results['detection_methods'].append('ner')
            logger.info(f"NER detection complete: {len(ner_results)} matches")
        
        # Process with GLiNER if requested
        if 'gliner' in methods and gliner_model is not None:
            gliner_results = detect_with_gliner_ml(text)
            results['results']['gliner'] = gliner_results
            results['detection_methods'].append('gliner')
            logger.info(f"GLiNER detection complete: {len(gliner_results)} matches")
        
        # Send results to aggregator service
        connection_out = pika.BlockingConnection(pika.URLParameters(RABBITMQ_URL))
        channel_out = connection_out.channel()
        channel_out.queue_declare(queue='aggregator_tasks')
        
        # Create response message
        response = {
            'job_id': job_id,
            'service': 'ml',
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
        logger.info(f"Job {job_id} chunk {chunk_idx+1}/{total_chunks} results sent to aggregator")
        
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
        channel.queue_declare(queue='ml_tasks')
        
        # Configure consumer
        channel.basic_qos(prefetch_count=1)
        channel.basic_consume(queue='ml_tasks', on_message_callback=callback)
        
        logger.info("ML Service started, waiting for messages...")
        
        # Start consuming
        channel.start_consuming()
    except Exception as e:
        logger.error(f"Critical error in ML service: {e}", exc_info=True)
        time.sleep(5)  # Wait before restarting
        main()  # Restart the service

if __name__ == "__main__":
    # Wait for RabbitMQ to be ready
    time.sleep(10)
    main()
