import torch
import numpy as np
import transformers
from typing import Dict, List, Any, Optional

from models.quantum_classifier import QuantumInspiredClassifier
from models.llm_classifier import LLMPIIClassifier
from utils.regex_patterns import PIIRegexPatterns
from utils.international_patterns import InternationalPIIPatterns
from utils.logger import setup_logger
from utils.presidio_integration import init_presidio_analyzer, detect_with_presidio
from utils.entity_recognition import load_model, detect_with_ner

# Set up logger
logger = setup_logger(__name__, log_file="/var/log/pii-guardian/detection.log")

class PIIDetectionService:
    """
    Comprehensive PII Detection Service
    Integrating Multiple Detection Techniques
    """
    
    def __init__(
        self, 
        config: Dict[str, Any] = None,
        llm_model: str = 'sentence-transformers/all-MiniLM-L6-v2',
        quantum_classifier: Optional[QuantumInspiredClassifier] = None
    ):
        """
        Initialize PII Detection Service
        
        :param config: Configuration dictionary
        :param llm_model: Pretrained LLM for semantic understanding
        :param quantum_classifier: Optional pre-trained quantum classifier
        """
        # Configuration management
        self.config = self._load_configuration(config)
        
        # Regex Pattern Management
        self.regex_patterns = PIIRegexPatterns.get_all_patterns()
        
        # Add international patterns to regex patterns
        if 'international' in self.config.get('detection_methods', []):
            international_patterns = InternationalPIIPatterns.add_patterns_to_regex_dict()
            self.regex_patterns.update(international_patterns)
        
        # Large Language Model Setup
        try:
            self.llm_tokenizer = transformers.AutoTokenizer.from_pretrained(llm_model)
            self.llm_model = transformers.AutoModel.from_pretrained(llm_model)
            
            # LLM-based PII classifier
            self.llm_classifier = LLMPIIClassifier(model=llm_model, device=self.config.get('device', 'cpu'))
        except Exception as e:
            logger.error(f"Error initializing LLM models: {e}", exc_info=True)
            self.llm_tokenizer = None
            self.llm_model = None
            self.llm_classifier = None
        
        # PII Detection Models
        try:
            self.ner_model = load_model()
        except Exception as e:
            logger.error(f"Error loading NER model: {e}", exc_info=True)
            self.ner_model = None
            
        try:
            self.presidio_analyzer = init_presidio_analyzer(
                languages=self.config.get('supported_languages', ['en'])
            )
        except Exception as e:
            logger.error(f"Error initializing Presidio analyzer: {e}", exc_info=True)
            self.presidio_analyzer = None
        
        # Quantum-Inspired Classifier
        self.quantum_classifier = (
            quantum_classifier or 
            self._initialize_default_quantum_classifier()
        )
        
        logger.info("PII Detection Service initialized successfully")
    
    def _load_configuration(self, config: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Load and validate configuration
        
        :param config: User-provided configuration
        :return: Processed configuration
        """
        default_config = {
            'detection_methods': ['regex', 'international', 'presidio', 'ner', 'llm_semantic', 'quantum_classification'],
            'supported_languages': ['en'],
            'supported_countries': ['US', 'AR'],
            'device': 'cpu',
            'confidence_threshold': 0.5
        }
        
        if config:
            # Merge user config with defaults
            for key, value in config.items():
                default_config[key] = value
        
        return default_config
    
    def _initialize_default_quantum_classifier(self):
        """
        Initialize a default quantum classifier
        
        :return: QuantumInspiredClassifier instance
        """
        try:
            model = QuantumInspiredClassifier(
                input_dim=100,
                num_classes=10,
                complexity_level=0.5
            )
            return model
        except Exception as e:
            logger.error(f"Error initializing quantum classifier: {e}", exc_info=True)
            return None
    
    def detect_pii(self, text: str, methods: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Comprehensive PII detection using multiple methods
        
        :param text: Input text
        :param methods: Detection methods to use (if None, use configured methods)
        :return: Detection results with confidence scores
        """
        methods = methods or self.config.get('detection_methods', [])
        
        results = []
        
        # Regex detection
        if 'regex' in methods:
            regex_results = self._detect_with_regex(text)
            results.extend(regex_results)
        
        # International pattern detection
        if 'international' in methods:
            international_results = self._detect_with_international(text)
            results.extend(international_results)
        
        # Microsoft Presidio detection
        if 'presidio' in methods and self.presidio_analyzer:
            presidio_results = self._detect_with_presidio(text)
            results.extend(presidio_results)
        
        # NER-based detection
        if 'ner' in methods and self.ner_model:
            ner_results = self._detect_with_ner(text)
            results.extend(ner_results)
        
        # LLM semantic detection
        if 'llm_semantic' in methods and self.llm_classifier:
            llm_results = self._detect_with_llm(text)
            results.extend(llm_results)
        
        # Quantum classification
        quantum_results = None
        if 'quantum_classification' in methods and self.quantum_classifier:
            quantum_results = self._classify_with_quantum(text)
        
        # Remove duplicates
        unique_results = self._deduplicate_results(results)
        
        # Calculate confidence scores
        confidence_scores = self._calculate_confidence_scores(unique_results)
        
        return {
            'pii_matches': unique_results,
            'pii_detected': len(unique_results) > 0,
            'confidence_scores': confidence_scores,
            'quantum_analysis': quantum_results
        }
    
    def _detect_with_regex(self, text: str) -> List[Dict[str, Any]]:
        """
        Regex-based PII detection
        
        :param text: Input text
        :return: List of regex matches
        """
        results = []
        
        for pii_type, pattern in self.regex_patterns.items():
            matches = pattern.findall(text)
            if matches:
                # Ensure matches are strings
                string_matches = [str(match) for match in matches]
                results.append({
                    'type': pii_type,
                    'matches': string_matches,
                    'detection_method': 'regex',
                    'confidence': 0.8  # Regex patterns usually have good precision
                })
        
        return results
    
    def _detect_with_international(self, text: str) -> List[Dict[str, Any]]:
        """
        International PII detection
        
        :param text: Input text
        :return: List of international matches
        """
        supported_countries = self.config.get('supported_countries', ['US'])
        
        all_results = []
        
        # Process for Argentina if supported
        if any(country in supported_countries for country in ['AR', 'ARG', 'ARGENTINA']):
            argentina_results = InternationalPIIPatterns.detect_argentina_pii(text)
            all_results.extend(argentina_results)
        
        # Add more countries as needed
        
        return all_results
    
    def _detect_with_llm(self, text: str) -> List[Dict[str, Any]]:
        """
        LLM-based semantic PII detection
        
        :param text: Input text
        :return: List of LLM-detected matches
        """
        try:
            return self.llm_classifier.detect_pii(text)
        except Exception as e:
            logger.error(f"Error in LLM detection: {e}", exc_info=True)
            return []
    
    def _classify_with_quantum(self, text: str) -> Dict[str, Any]:
        """
        Quantum-inspired classification
        
        :param text: Input text
        :return: Classification results
        """
        try:
            # Generate embedding from text
            device = self.config.get('device', 'cpu')
            embedding = self.llm_classifier._generate_embedding(text).to(device)
            
            # Prepare input for quantum classifier
            features = embedding.view(-1)[:100]  # Truncate/pad to 100 dim
            
            with torch.no_grad():
                outputs = self.quantum_classifier(features.unsqueeze(0))
                probabilities = torch.softmax(outputs, dim=1).squeeze(0)
                
                # Get uncertainty metrics
                uncertainty = self.quantum_classifier.compute_uncertainty(probabilities)
                
                # Get classification results
                _, predicted_class = torch.max(probabilities, 0)
                
                return {
                    'pii_probability': probabilities[0].item(),  # Probability of being PII
                    'predicted_class': predicted_class.item(),
                    'uncertainty': uncertainty,
                    'detection_method': 'quantum_classification'
                }
        except Exception as e:
            logger.error(f"Error in quantum classification: {e}", exc_info=True)
            return {
                'pii_probability': 0.0,
                'predicted_class': 0,
                'uncertainty': {'shannon_entropy': 0.0, 'uncertainty_principle': 0.0, 'probabilistic_variance': 0.0},
                'detection_method': 'quantum_classification'
            }
    
    def _detect_with_ner(self, text: str) -> List[Dict[str, Any]]:
        """
        NER-based entity detection 
        
        :param text: Input text
        :return: List of entity matches
        """
        entity_mapping = {
            "PERSON": "person_name",
            "ORG": "organization",
            "GPE": "location",
            "LOC": "location",
            "MONEY": "financial",
            "CARDINAL": "number",
            "DATE": "date"
        }
        
        try:
            return detect_with_ner(text, self.ner_model, entity_mapping)
        except Exception as e:
            logger.error(f"NER detection error: {e}", exc_info=True)
            return []
    
    def _detect_with_gliner(self, text: str) -> List[Dict[str, Any]]:
        """
        NER-based entity detection (formerly GLiNER)
        
        :param text: Input text
        :return: List of entity matches
        """
        try:
            # Request entity types that are relevant for PII
            entities = ['PERSON', 'ORGANIZATION', 'LOCATION', 'FINANCIAL_INFO', 'NUMBER', 'DATE']
            gliner_results = self.ner_model.predict(text, entities)
            
            # Convert to standard format
            return [{
                'type': entity['label'].lower(),
                'matches': [entity['text']],
                'detection_method': 'ner',
                'location': {'start': entity['start'], 'end': entity['end']}
            } for entity in gliner_results]
        except Exception as e:
            logger.error(f"NER detection error: {e}", exc_info=True)
            return []
    
    def _detect_with_presidio(self, text: str) -> List[Dict[str, Any]]:
        """
        Microsoft Presidio PII detection
        
        :param text: Input text
        :return: List of Presidio matches
        """
        try:
            entities = [
                'PERSON', 
                'EMAIL_ADDRESS', 
                'PHONE_NUMBER', 
                'US_SSN',
                'CREDIT_CARD',
                'IBAN_CODE',
                'PASSPORT',
                'DRIVER_LICENSE'
            ]
            
            # Add international entities if needed
            if 'international' in self.config.get('detection_methods', []):
                if 'AR' in self.config.get('supported_countries', []):
                    entities.extend(['ID_NUMBER', 'DOMAIN_NAME', 'LOCATION'])
            
            return detect_with_presidio(text, self.presidio_analyzer, entities)
        except Exception as e:
            logger.error(f"Presidio detection error: {e}", exc_info=True)
            return []
    
    def _deduplicate_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Remove duplicate PII detections
        
        :param results: List of detection results
        :return: Deduplicated list
        """
        # Create a unique key for each match
        seen = set()
        unique_results = []
        
        for result in results:
            pii_type = result.get('type', '').lower()
            
            # Handle different match formats
            matches = result.get('matches', [])
            if isinstance(matches, list):
                matches_key = tuple(sorted([str(m).lower() for m in matches]))
            else:
                matches_key = str(matches).lower()
            
            result_key = (pii_type, matches_key)
            
            if result_key not in seen:
                seen.add(result_key)
                unique_results.append(result)
        
        return unique_results
    
    def _calculate_confidence_scores(self, results: List[Dict[str, Any]]) -> Dict[str, float]:
        """
        Calculate confidence scores for detection methods
        
        :param results: Detection results
        :return: Confidence scores by method
        """
        # Count detections by method
        method_counts = {}
        for result in results:
            method = result.get('detection_method', 'unknown')
            method_counts[method] = method_counts.get(method, 0) + 1
        
        # Normalize
        total = sum(method_counts.values()) or 1
        confidence_scores = {
            method: count / total 
            for method, count in method_counts.items()
        }
        
        return confidence_scores
