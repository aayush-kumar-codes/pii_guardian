import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

try:
    from presidio_analyzer import AnalyzerEngine
    from presidio_analyzer.nlp_engine import NlpEngineProvider

    PRESIDIO_AVAILABLE = True

    def init_presidio_analyzer(languages=["en"]):
        """Initialize the Presidio analyzer with specified languages"""
        try:
            # Create NLP engine based on spaCy
            nlp_engine = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": lang, "model_name": f"{lang}_core_web_sm"} for lang in languages]
            }).create_engine()

            # Create analyzer with the given engine
            return AnalyzerEngine(nlp_engine=nlp_engine)
        except Exception as e:
            logger.error(f"Error initializing Presidio analyzer: {e}", exc_info=True)
            return MockPresidioAnalyzer()

except ImportError:
    PRESIDIO_AVAILABLE = False

    # Mock implementation for when Presidio is not available
    class MockPresidioAnalyzer:
        """Mock implementation of Presidio Analyzer for when the library is not available"""

        def analyze(self, text, entities=None, language="en"):
            """Mock analyze method"""
            logger.warning("Using mock Presidio analyzer - no PII will be detected")
            return []


def detect_with_presidio(text: str, analyzer, entities=None) -> List[Dict[str, Any]]:
    """
    Detect PII using Microsoft Presidio

    :param text: Text to analyze
    :param analyzer: Presidio AnalyzerEngine instance
    :param entities: List of entity types to detect
    :return: List of detected PII
    """
    if not PRESIDIO_AVAILABLE:
        return []

    if entities is None:
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

    try:
        # Analyze text with Presidio
        analyzer_results = analyzer.analyze(
            text=text,
            entities=entities,
            language="en"
        )

        # Format results
        results = []
        for result in analyzer_results:
            results.append({
                'type': result.entity_type.lower(),
                'matches': [text[result.start:result.end]],
                'detection_method': 'presidio',
                'confidence': result.score,
                'location': {'start': result.start, 'end': result.end}
            })

        return results

    except Exception as e:
        logger.error(f"Error in Presidio detection: {e}", exc_info=True)
        return []
