import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

try:
    import spacy

    SPACY_AVAILABLE = True

    def load_ner_model(model_name="en_core_web_sm"):
        """Load a spaCy NER model"""
        try:
            return spacy.load(model_name)
        except Exception as e:
            logger.error(f"Error loading spaCy model: {e}", exc_info=True)
            return MockNERModel()

except ImportError:
    SPACY_AVAILABLE = False

    # Mock implementation for when spaCy is not available
    class MockNERModel:
        """Mock implementation of spaCy NER model"""

        def __call__(self, text):
            """Mock prediction method"""
            logger.warning("Using mock NER model - no entities will be detected")
            return MockDoc(text)


class MockDoc:
    """Mock spaCy Doc object"""

    def __init__(self, text):
        self.text = text
        self.ents = []


def detect_with_ner(text: str, model, entity_mapping=None) -> List[Dict[str, Any]]:
    """
    Detect entities using spaCy NER

    :param text: Text to analyze
    :param model: spaCy model
    :param entity_mapping: Mapping from spaCy entity types to PII types
    :return: List of detected entities
    """
    if not SPACY_AVAILABLE:
        return []

    if entity_mapping is None:
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
        # Process text with spaCy
        doc = model(text)

        # Extract entities
        results = []
        for ent in doc.ents:
            pii_type = entity_mapping.get(ent.label_, ent.label_.lower())

            results.append({
                'type': pii_type,
                'matches': [ent.text],
                'detection_method': 'ner',
                'confidence': 0.7,  # spaCy doesn't provide confidence scores
                'location': {'start': ent.start_char, 'end': ent.end_char}
            })

        return results

    except Exception as e:
        logger.error(f"Error in NER detection: {e}", exc_info=True)
        return []


# This simulates the fictional GLiNER interface for backward compatibility
class CustomEntityRecognizer:
    """
    Custom entity recognizer that provides a GLiNER-like interface
    using spaCy under the hood
    """

    def __init__(self, model_name="en_core_web_sm"):
        """Initialize with a spaCy model"""
        self.model = load_ner_model(model_name)

        # Define entity mappings (spaCy entity types to PII types)
        self.entity_mapping = {
            "PERSON": "PERSON",
            "ORG": "ORGANIZATION",
            "GPE": "LOCATION",
            "LOC": "LOCATION",
            "MONEY": "FINANCIAL_INFO",
            "CARDINAL": "NUMBER",
            "DATE": "DATE"
        }

    def predict(self, text: str, entities: List[str]) -> List[Dict[str, Any]]:
        """
        Predict entities in text (GLiNER-like interface)

        :param text: Text to analyze
        :param entities: List of entity types to detect
        :return: List of detected entities
        """
        # Process text with spaCy
        doc = self.model(text)

        # Extract and filter entities
        results = []
        for ent in doc.ents:
            if ent.label_ in self.entity_mapping and self.entity_mapping[ent.label_] in entities:
                results.append({
                    'type': self.entity_mapping[ent.label_],
                    'matches': [ent.text],
                    'detection_method': 'ner',
                    'confidence': 0.7,
                    'location': {'start': ent.start_char, 'end': ent.end_char}
                })

        return results
