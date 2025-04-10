import os
import json
import torch
import numpy as np
from typing import Dict, List, Any, Optional
import openai

class LLMPIIClassifier:
    """
    PII Classifier using OpenAI's Large Language Models
    
    Detects Personally Identifiable Information (PII)
    """
    
    def __init__(
        self, 
        api_key: Optional[str] = None,
        max_tokens: int = 1000,
        temperature: float = 0.2,
        model: str = 'gpt-4-turbo',
        device: str = "cpu"
    ):
        """
        Initialize the OpenAI-based PII classifier
        
        :param api_key: OpenAI API key
        :param max_tokens: Maximum tokens for LLM response
        :param temperature: Sampling temperature for LLM
        :param model: OpenAI model to use
        :param device: Device to use for embedding calculations ("cpu" or "cuda")
        """
        # Set up API key
        self.api_key = api_key or os.getenv('OPENAI_API_KEY')
        if not self.api_key:
            raise ValueError("OpenAI API key must be provided either as an argument or in OPENAI_API_KEY environment variable")
        
        # Configure OpenAI client
        openai.api_key = self.api_key
        
        # Configuration parameters
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.model = model
        self.device = device
        
        # PII types to detect
        self.pii_types = [
            'person_name',
            'email',
            'phone_number',
            'physical_address',
            'social_security_number',
            'credit_card_number',
            'passport_number',
            'tax_id',
            'financial_account',
            'driver_license',
            'ip_address'
        ]
        
        # Initialize embedding model
        try:
            import torch
            from transformers import AutoTokenizer, AutoModel
            self.tokenizer = AutoTokenizer.from_pretrained("sentence-transformers/all-MiniLM-L6-v2")
            self.embedding_model = AutoModel.from_pretrained("sentence-transformers/all-MiniLM-L6-v2").to(device)
        except ImportError:
            self.tokenizer = None
            self.embedding_model = None
    
    def detect_pii(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect PII in text using OpenAI
        
        :param text: Input text
        :return: List of detected PII instances
        """
        # Prepare prompt for PII detection
        prompt = self._construct_pii_detection_prompt(text)
        
        # Call OpenAI
        response = self._call_openai(prompt)
        
        # Parse response
        return self._parse_pii_response(response, text)
    
    def _generate_embedding(self, text: str) -> torch.Tensor:
        """
        Generate embedding for text using a transformer model
        
        :param text: Input text
        :return: Embedding tensor
        """
        if self.tokenizer is None or self.embedding_model is None:
            # Return a dummy embedding if models aren't loaded
            return torch.zeros(1, 384).to(self.device)
        
        # Tokenize and get embeddings
        inputs = self.tokenizer(text, padding=True, truncation=True, 
                               max_length=512, return_tensors="pt").to(self.device)
        
        with torch.no_grad():
            model_output = self.embedding_model(**inputs)
            
        # Use mean pooling to get a fixed-size embedding
        attention_mask = inputs['attention_mask']
        token_embeddings = model_output[0]
        
        # Calculate mean embedding (ignoring padding tokens)
        input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
        sum_embeddings = torch.sum(token_embeddings * input_mask_expanded, 1)
        sum_mask = torch.clamp(input_mask_expanded.sum(1), min=1e-9)
        mean_embedding = sum_embeddings / sum_mask
        
        return mean_embedding
    
    def _construct_pii_detection_prompt(self, text: str) -> str:
        """
        Construct a detailed prompt for PII detection
        
        :param text: Input text
        :return: Formatted prompt for OpenAI
        """
        pii_types_str = ", ".join(self.pii_types)
        
        prompt = f"""You are a highly skilled PII (Personally Identifiable Information) detection expert. 
Your task is to carefully analyze the following text and identify any instances of sensitive personal information.

Potential PII types to detect: {pii_types_str}

Detailed Guidelines:
1. Be extremely thorough in detection
2. Consider contextual nuances
3. Provide a comprehensive analysis
4. Minimize false positives
5. Be precise in identifying exact matches

Input Text:
```
{text}
```

Respond ONLY with a JSON-formatted list of detected PII instances. 
Each instance MUST include these exact keys:
- type: The specific type of PII detected
- value: The exact text of the PII
- confidence: A confidence score between 0.0 and 1.0
- start_index: Starting character index in the original text
- end_index: Ending character index in the original text

JSON RESPONSE ONLY. No additional explanation."""
        
        return prompt
    
    def _call_openai(self, prompt: str) -> str:
        """
        Call OpenAI's API
        
        :param prompt: Formatted prompt
        :return: LLM response
        """
        try:
            response = openai.ChatCompletion.create(
                model=self.model,
                temperature=self.temperature,
                max_tokens=self.max_tokens,
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            return response.choices[0].message.content
        except Exception as e:
            print(f"OpenAI API Error: {e}")
            return "[]"
    
    def _parse_pii_response(self, response: str, original_text: str) -> List[Dict[str, Any]]:
        """
        Parse the OpenAI's JSON response
        
        :param response: Raw LLM response
        :param original_text: Original input text
        :return: Parsed PII instances
        """
        # Clean and parse response
        try:
            # Multiple parsing attempts for robustness
            try:
                # Direct JSON parsing
                pii_list = json.loads(response)
            except json.JSONDecodeError:
                # Extract JSON from code blocks or between brackets
                import re
                json_matches = re.findall(r'(\[{.*?}\])', response, re.DOTALL)
                if json_matches:
                    pii_list = json.loads(json_matches[0])
                else:
                    return []
            
            # Validate and clean PII instances
            validated_pii = []
            for pii in pii_list:
                # Ensure all required keys are present
                if all(key in pii for key in ['type', 'value', 'confidence', 'start_index', 'end_index']):
                    # Validate start and end indices
                    try:
                        start = int(pii['start_index'])
                        end = int(pii['end_index'])
                        
                        # Double-check the value matches the original text
                        if original_text[start:end] == pii['value']:
                            # Format matches to match the expected structure in aggregator
                            validated_match = {
                                'type': pii['type'],
                                'matches': [pii['value']],
                                'detection_method': 'llm_semantic',
                                'confidence': pii['confidence']
                            }
                            validated_pii.append(validated_match)
                    except (ValueError, IndexError):
                        pass
            
            return validated_pii
        
        except Exception as e:
            print(f"PII Parsing Error: {e}")
            return []
    
    def add_custom_pii_type(self, pii_type: str) -> None:
        """
        Add a custom PII type to detection
        
        :param pii_type: New PII type to detect
        """
        if pii_type not in self.pii_types:
            self.pii_types.append(pii_type)
