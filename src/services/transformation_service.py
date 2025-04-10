import hashlib
import uuid
from typing import Dict, Any, Optional

class DataTransformationService:
    """
    Advanced Data Transformation Service
    Supports multiple PII anonymization techniques
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        Initialize transformation service
        
        :param config: Configuration dictionary
        """
        # Default configuration
        self.config = config or {
            'anonymization': {
                'method': 'pseudonymize',
                'preserve_context': True,
                'consistency_salt': str(uuid.uuid4())
            }
        }
        
        # Transformation methods mapping
        self.transformation_methods = {
            'pseudonymize': self._pseudonymize,
            'anonymize': self._anonymize,
            'tokenize': self._tokenize,
            'mask': self._mask
        }
    
    def transform_data(
        self, 
        text: str, 
        detection_results: Dict[str, Any]
    ) -> str:
        """
        Transform text based on PII detection results
        
        :param text: Input text
        :param detection_results: PII detection results
        :return: Transformed text
        """
        # Get transformation method from config
        method = self.config.get('anonymization', {}).get(
            'method', 
            'pseudonymize'
        )
        
        # Select transformation method
        transform_func = self.transformation_methods.get(
            method, 
            self._pseudonymize
        )
        
        return transform_func(text, detection_results)
    
    def _generate_consistent_token(
        self, 
        original: str, 
        pii_type: str
    ) -> str:
        """
        Generate consistent anonymization token
        
        :param original: Original PII value
        :param pii_type: Type of PII
        :return: Consistent anonymized token
        """
        # Use salted hash for consistent transformation
        salt = self.config['anonymization'].get('consistency_salt', '')
        hash_input = f"{salt}_{pii_type}_{original}"
        
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]
    
    def _pseudonymize(
        self, 
        text: str, 
        detection_results: Dict[str, Any]
    ) -> str:
        """
        Pseudonymize detected PII
        Replace with consistent tokens
        
        :param text: Input text
        :param detection_results: PII detection results
        :return: Pseudonymized text
        """
        transformed_text = text
        
        for match in detection_results.get('pii_matches', []):
            for individual_match in match.get('matches', []):
                # Generate consistent pseudonym
                pseudonym = self._generate_consistent_token(
                    individual_match, 
                    match.get('type', 'PII')
                )
                
                # Replace in text
                transformed_text = transformed_text.replace(
                    individual_match, 
                    f"[{match.get('type', 'PII')}_{pseudonym}]"
                )
        
        return transformed_text
    
    def _anonymize(
        self, 
        text: str, 
        detection_results: Dict[str, Any]
    ) -> str:
        """
        Completely anonymize detected PII
        
        :param text: Input text
        :param detection_results: PII detection results
        :return: Anonymized text
        """
        transformed_text = text
        
        for match in detection_results.get('pii_matches', []):
            for individual_match in match.get('matches', []):
                # Replace with generic anonymization marker
                transformed_text = transformed_text.replace(
                    individual_match, 
                    f"[{match.get('type', 'PII')}_ANONYMIZED]"
                )
        
        return transformed_text
    
    def _tokenize(
        self, 
        text: str, 
        detection_results: Dict[str, Any]
    ) -> str:
        """
        Tokenize detected PII
        
        :param text: Input text
        :param detection_results: PII detection results
        :return: Tokenized text
        """
        transformed_text = text
        
        for match in detection_results.get('pii_matches', []):
            for individual_match in match.get('matches', []):
                # Generate unique token
                token = str(uuid.uuid4())[:8]
                
                transformed_text = transformed_text.replace(
                    individual_match, 
                    f"[{match.get('type', 'PII')}_{token}]"
                )
        
        return transformed_text
    
    def _mask(
        self, 
        text: str, 
        detection_results: Dict[str, Any]
    ) -> str:
        """
        Mask detected PII
        
        :param text: Input text
        :param detection_results: PII detection results
        :return: Masked text
        """
        transformed_text = text
        
        for match in detection_results.get('pii_matches', []):
            for individual_match in match.get('matches', []):
                # Create mask based on original length
                mask = '*' * len(individual_match)
                
                transformed_text = transformed_text.replace(
                    individual_match, 
                    mask
                )
        
        return transformed_text
    
    def set_transformation_method(self, method: str) -> None:
        """
        Set the transformation method to use
        
        :param method: Transformation method name
        """
        if method not in self.transformation_methods:
            raise ValueError(f"Unknown transformation method: {method}")
        
        self.config['anonymization']['method'] = method
    
    def generate_transformation_report(
        self, 
        original_text: str, 
        transformed_text: str, 
        detection_results: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Generate a report on the transformation process
        
        :param original_text: Original input text
        :param transformed_text: Transformed output text
        :param detection_results: Detection results used for transformation
        :return: Transformation report
        """
        # Calculate transformation statistics
        total_pii_instances = sum(
            len(match.get('matches', [])) 
            for match in detection_results.get('pii_matches', [])
        )
        
        # Count PII types
        pii_types = {}
        for match in detection_results.get('pii_matches', []):
            pii_type = match.get('type', 'unknown')
            pii_types[pii_type] = pii_types.get(pii_type, 0) + len(match.get('matches', []))
        
        # Calculate transformation impact
        transformation_impact = 0
        if len(original_text) > 0:
            transformation_impact = 1 - (len(transformed_text) / len(original_text))
        
        return {
            'transformation_method': self.config['anonymization']['method'],
            'total_pii_instances': total_pii_instances,
            'pii_types_identified': pii_types,
            'transformation_impact': transformation_impact,
            'preserved_context': self.config['anonymization'].get('preserve_context', True)
        }
