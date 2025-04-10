import re
from typing import Dict, Pattern, List, Any

class InternationalPIIPatterns:
    """
    International PII detection patterns
    Extends core PII detection with country-specific patterns
    """
    
    # Argentina PII Patterns
    ARGENTINA_PII_PATTERNS: Dict[str, Dict[str, Any]] = {
        'argentina_dni': {
            'pattern': re.compile(r'(?<![-−―–——@&*$!?%]|\d\.)\b[1-9]\d([-−―–——.·]?)\d{3}\1\d{3}\b(?![-−―–——@&*$!?%]|[\-.]\d)'),
            'context': re.compile(r'(?i)(?:Argentin(?:[ae]|ian)[\s_]{0,3}(?:National[\s_]{0,3}Id(?:entity)?(?:[\s_]{0,3}(?:[#№]|n(?:[°º˚]|umbers?|o(?:\b|_))))?|DNI)|d(?:\.n\.i|ni(?:\b|_)|ocumento[\s_]{0,3}nacional[\s_]{0,3}de[\s_]{0,3}identidad))(?:[\s_]{0,3}argentin[ao])?'),
            'description': 'Argentinian DNI Number (National ID)',
            'countries': ['AR'],
            'confidence': 0.8,
            'example': '34960099'
        },
        'argentina_dni_dot': {
            'pattern': re.compile(r'(?<![-−―–——@&*$!?%]|\d\.)\b[1-9]\d\.\d{3}\.\d{3}\b(?![−―–——@&*$%-]|\.\d)'),
            'context': re.compile(r'(?i)(?:Argentin(?:[ae]|ian)[\s_]{0,3}(?:National[\s_]{0,3}Id(?:entity)?(?:[\s_]{0,3}(?:[#№]|n(?:[°º˚]|umbers?|o(?:\b|_))))?|DNI)|d(?:\.n\.i|ni(?:\b|_)|ocumento[\s_]{0,3}nacional[\s_]{0,3}de[\s_]{0,3}identidad))(?:[\s_]{0,3}argentin[ao])?'),
            'description': 'Argentinian DNI Number with dot separators',
            'countries': ['AR'],
            'confidence': 0.85,
            'example': '22.105.779'
        },
        'argentina_drivers_license': {
            'pattern': re.compile(r'(?<![-−―–——@&*$!?%]|\d\.)(?!(\d)\1[-−―–——.·]?\1{3}[-−―–——.·]?\1{3}|1(?:0[-−―–——.·]?101[-−―–——.·]?010|2[-−―–——.·]?345[-−―–——.·]?678))\b[1-9]\d([-−―–——.·]?)\d{3}\2\d{3}\b(?![-−―–——@&*$!?%]|[\-.]\d)'),
            'context': re.compile(r'(?i)(?:(?:\b|_)L(?:icencia(?:[\s_]{0,3}nacional)?[\s_]{0,3}de[\s_]{0,3}conducir(?:[\s_]{0,3}(?:arg(?:entina|\b)|digital(?:[\s_]{0,3}(?:de[\s_]{0,3})?arg(?:entina|\b))?)?)?|ncd?(?:(?:[\s_]{0,3}de)?[\s_]{0,3}arg(?:entina)?|(?:\b|_)))|N(?:[°º˚]|[uúÚ]mero)(?:[\s_]{0,3}(?:de[\s_]{0,3})?licencia(?:[\s_]{0,3}Nacional)?[\s_]{0,3}de[\s_]{0,3}conducir(?:(?:[\s_]{0,3}de)?[\s_]{0,3}arg(?:entina)?)?)|driv(?:er\'?s|ing)[\s_]{0,3}licenses?(?:[\s_]{0,3}(?:[#№]|n(?:[º°]|[or](?:\b|_)|umbers?)))?(?:[\s_]{0,3}(?:argentina|\(argentina\)))|arg(?:entin(?:a|ian))?[\s_]{0,3}driv(?:er\'?s|ing)[\s_]{0,3}licenses?(?:[\s_]{0,3}(?:[#№]|n(?:[º°]|[or](?:\b|_)|umbers?)))?'),
            'description': 'Argentinian Driver\'s License Number',
            'countries': ['AR'],
            'confidence': 0.75,
            'example': '25-042-095'
        },
        'argentina_cuil': {
            'pattern': re.compile(r'(?<![\-‐‑‒–—―\.\$@])\b2(?:[047]([\-‐‑‒–—―]?)\d{8}\1\d|3([\-‐‑‒–—―]?)\d{8}\2[349])\b(?![\-‐‑‒–—―\$@]|\.\d)'),
            'context': None,  # No specific context pattern provided
            'description': 'Argentinian Employment Identification Number (CUIL)',
            'countries': ['AR'],
            'confidence': 0.85,
            'example': '20-22375732-5'
        },
        'argentina_passport': {
            'pattern': re.compile(r'(?<![-‐‑‒–—―%*$@])\b(?:(?:A{2}[A-Z]|Z{3})(?!(\d)\1{5}|1(?:23456|01010)|010101)\d{6}|(?!(\d)\2{7}|1(?:2345678|0101010))[1-9]\d{7}N)\b(?![-‐‑‒–—―%@$%*]|\.\d)'),
            'context': re.compile(r'\b(?i)(?:pas(?:aporte[\-‐‑‒–—―–\s ]{0,3}(?:arg(?:entino)?|de[\-‐‑‒–—―–\s ]{0,3}la[\-‐‑‒–—―–\s ]{0,3}rep[úuÚ]blica[\-‐‑‒–—―–\s ]{0,3}argentina)|sport(?:[\s_]{0,3}n(?:[°º˚]|umbers?|o(?:\b|_)))?)|argentin(?:a|ian)[\s_]{0,3}(?:passport|travel[\s_]{0,3}document)(?:[\s_]{0,3}n(?:[°º˚]|umbers?|o(?:\b|_)))?|travel[\s_]{0,3}document(?:[\s_]{0,3}n(?:[°º˚]|umbers?|o(?:\b|_)))?)'),
            'description': 'Argentinian Passport Number',
            'countries': ['AR'],
            'confidence': 0.8,
            'example': 'AAA732750'
        }
    }
    
    @classmethod
    def get_argentina_patterns(cls) -> Dict[str, Dict[str, Any]]:
        """
        Get Argentinian PII patterns
        
        :return: Dictionary of Argentinian PII patterns
        """
        return cls.ARGENTINA_PII_PATTERNS
    
    @classmethod
    def detect_argentina_pii(cls, text: str) -> List[Dict[str, Any]]:
        """
        Detect Argentinian PII in text
        
        :param text: Input text
        :return: List of detected PII matches
        """
        matches = []
        
        for pii_id, pii_info in cls.ARGENTINA_PII_PATTERNS.items():
            pattern = pii_info['pattern']
            context_pattern = pii_info.get('context')
            found_matches = pattern.findall(text)
            
            if found_matches:
                # If context pattern exists, check if context is present
                if context_pattern and not context_pattern.search(text):
                    continue
                
                # Clean up matches if they have groups
                cleaned_matches = []
                for match in found_matches:
                    if isinstance(match, tuple):
                        # Use the original text to find the actual matched string
                        for match_start in range(len(text)):
                            match_text = text[match_start:match_start+20]  # Arbitrary window size
                            if pattern.search(match_text):
                                actual_match = pattern.search(match_text).group(0)
                                cleaned_matches.append(actual_match)
                                break
                    else:
                        cleaned_matches.append(match)
                
                if cleaned_matches:
                    matches.append({
                        'type': pii_id,
                        'matches': cleaned_matches,
                        'detection_method': 'international_regex',
                        'confidence': pii_info.get('confidence', 0.75),
                        'country': pii_info.get('countries', ['AR'])[0],
                        'description': pii_info.get('description', '')
                    })
        
        return matches
    
    @classmethod
    def add_patterns_to_regex_dict(cls) -> Dict[str, Pattern]:
        """
        Get all international patterns to add to regex patterns dictionary
        
        :return: Dictionary of additional patterns
        """
        additional_patterns = {}
        
        # Add Argentinian patterns
        for pattern_id, pattern_info in cls.ARGENTINA_PII_PATTERNS.items():
            additional_patterns[pattern_id] = pattern_info['pattern']
        
        # Add patterns from other countries as needed
        
        return additional_patterns
