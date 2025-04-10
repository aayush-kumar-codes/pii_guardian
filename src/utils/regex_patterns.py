from typing import Dict, Pattern, List, Union
import regex as re


__all__ = ["PIIRegexPatterns"]


class PIIRegexPatterns:
    """
    Comprehensive Regex Patterns for PII Detection
    """

    COMPREHENSIVE_PII_PATTERNS: Dict[str, Pattern] = {
        # Personal Identification
        "social_security": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "passport": re.compile(r"\b[A-Z]{1,2}\d{6,9}\b"),
        "driver_license": re.compile(r"\b[A-Z]{1,2}\d{4,9}\b"),

        # Contact Information
        "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", re.IGNORECASE),
        "phone": re.compile(r"\b(?:\+\d{1,2}\s?)?(?:\(\d{3}\)|\d{3})[\s.-]?\d{3}[\s.-]?\d{4}\b"),
        "address": re.compile(r"\d+\s+[A-Za-z\s]+(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr)\b", re.IGNORECASE),

        # Financial Information
        "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
        "bank_account": re.compile(r"\b\d{9,18}\b"),

        # Unique Identifiers
        "tax_id": re.compile(r"\b\d{2}-\d{7}\b"),
        "employee_id": re.compile(r"\b[A-Z]{2}\d{4,6}\b"),

        # Advanced Patterns
        "medical_record": re.compile(r"\b[A-Z]{2,3}\d{6,8}\b"),
        "insurance_number": re.compile(r"\b\d{3}\s?\d{2}\s?\d{4}\b")
    }

    @classmethod
    def get_pattern(cls, pattern_name: str) -> Union[Pattern, None]:
        """
        Retrieve a specific PII regex pattern.

        :param pattern_name: Name of the pattern to retrieve.
        :return: Compiled regex pattern or None if not found.
        """
        return cls.COMPREHENSIVE_PII_PATTERNS.get(pattern_name)

    @classmethod
    def match_pii(cls, text: str, pattern_name: str) -> List[str]:
        """
        Find all matches for a specific PII pattern in the given text.

        :param text: Input text to search.
        :param pattern_name: Name of the pattern to match.
        :return: List of matched PII instances.
        """
        pattern = cls.get_pattern(pattern_name)
        return pattern.findall(text) if pattern else []

    @classmethod
    def validate_pii(cls, value: str, pattern_name: str) -> bool:
        """
        Validate if a value matches a specific PII pattern exactly.

        :param value: Value to validate.
        :param pattern_name: Name of the pattern to validate against.
        :return: True if value fully matches the pattern, False otherwise.
        """
        pattern = cls.get_pattern(pattern_name)
        return bool(pattern and pattern.fullmatch(value))

    @classmethod
    def get_all_patterns(cls) -> Dict[str, Pattern]:
        """
        Retrieve all available PII regex patterns.

        :return: Dictionary of all compiled regex patterns.
        """
        return cls.COMPREHENSIVE_PII_PATTERNS
