
import re
from typing import List

from presidio_analyzer import (
    AnalyzerEngine,
    RecognizerResult,
    PatternRecognizer,
    Pattern,
    RecognizerRegistry,
    EntityRecognizer,
    AnalysisExplanation,
)
from presidio_analyzer.nlp_engine import NlpEngineProvider
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig


# ─────────────────────────────────────────────────────────────────────────────
# CUSTOMIZATION 1: Custom Recognizer — API Keys & Internal IDs
# ─────────────────────────────────────────────────────────────────────────────

class APIKeyRecognizer(PatternRecognizer):


    PATTERNS = [
        Pattern(
            name="api_key_generic",
            regex=r"\b(sk|pk|api|secret|token)[_\-][A-Za-z0-9]{20,}\b",
            score=0.85
        ),
        Pattern(
            name="internal_employee_id",
            regex=r"\bEMP[-_][0-9]{3,6}\b",
            score=0.90
        ),
        Pattern(
            name="internal_project_id",
            regex=r"\bPROJ[-_][A-Z0-9]{4,10}\b",
            score=0.90
        ),
        Pattern(
            name="bearer_token",
            regex=r"Bearer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}",
            score=0.95
        ),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="API_KEY_OR_INTERNAL_ID",
            patterns=self.PATTERNS,
            context=["api", "key", "token", "secret", "employee", "project", "authorization"],
            name="APIKeyRecognizer"
        )


# ─────────────────────────────────────────────────────────────────────────────
# CUSTOMIZATION 2: Context-Aware Scoring Recognizer
# Boosts confidence when surrounding words suggest sensitive context
# ─────────────────────────────────────────────────────────────────────────────

class ContextAwarePhoneRecognizer(PatternRecognizer):

    PATTERNS = [
        Pattern(
            name="phone_intl",
            regex=r"\+?[0-9]{1,3}[\s\-]?(\([0-9]{1,4}\)[\s\-]?)?[0-9]{6,12}",
            score=0.40     
        ),
        Pattern(
            name="phone_pk",           # Pakistani mobile format
            regex=r"\b0?3[0-9]{2}[\s\-]?[0-9]{7}\b",
            score=0.55
        ),
    ]

    CONTEXT_KEYWORDS = [
        "call", "phone", "contact", "mobile", "reach", "dial",
        "whatsapp", "number", "cell"
    ]

    def __init__(self):
        super().__init__(
            supported_entity="PHONE_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT_KEYWORDS,
            name="ContextAwarePhoneRecognizer"
        )

    def analyze(self, text: str, entities: List[str], nlp_artifacts=None) -> List[RecognizerResult]:
        results = super().analyze(text, entities, nlp_artifacts)
        boosted = []
        for r in results:
            window_start = max(0, r.start - 50)
            window_end = min(len(text), r.end + 50)
            context_window = text[window_start:window_end].lower()
            if any(kw in context_window for kw in self.CONTEXT_KEYWORDS):
                boosted_score = min(r.score + 0.40, 1.0)
                boosted.append(RecognizerResult(
                    entity_type=r.entity_type,
                    start=r.start,
                    end=r.end,
                    score=boosted_score,
                    analysis_explanation=r.analysis_explanation,
                    recognition_metadata=r.recognition_metadata
                ))
            else:
                boosted.append(r)
        return boosted


# ─────────────────────────────────────────────────────────────────────────────
# CUSTOMIZATION 3: Composite Entity Detection
# Detects combined PII patterns (name + email in same sentence)
# ─────────────────────────────────────────────────────────────────────────────

class CompositeIdentityRecognizer(PatternRecognizer):

    PATTERNS = [
        Pattern(
            name="name_email_composite",
            # Matches: word capitalized name + email in proximity
            regex=r"[A-Z][a-z]+ [A-Z][a-z]+\s.{0,30}[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}",
            score=0.88
        ),
        Pattern(
            name="id_and_dob_composite",
            # Matches ID-like number + date pattern nearby
            regex=r"\b[A-Z]{1,2}[0-9]{6,9}\b.{0,40}\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b",
            score=0.85
        ),
    ]

    def __init__(self):
        super().__init__(
            supported_entity="COMPOSITE_IDENTITY",
            patterns=self.PATTERNS,
            context=["contact", "identity", "details", "information", "profile"],
            name="CompositeIdentityRecognizer"
        )


# ─────────────────────────────────────────────────────────────────────────────
# Main Presidio Wrapper
# ─────────────────────────────────────────────────────────────────────────────

class PresidioAnalyzerWrapper:

    DEFAULT_ENTITIES = [
        "PERSON", "EMAIL_ADDRESS", "CREDIT_CARD", "IBAN_CODE",
        "IP_ADDRESS", "URL", "LOCATION", "DATE_TIME",
        "NRP",                    # Nationality / Religion / Political group
        "PHONE_NUMBER",
        "API_KEY_OR_INTERNAL_ID",
        "COMPOSITE_IDENTITY",
    ]

    def __init__(self, score_threshold: float = 0.4, language: str = "en"):
        self.score_threshold = score_threshold
        self.language = language
        self._setup_engine()
        self._anonymizer = AnonymizerEngine()

    def _setup_engine(self):
        try:
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}]
            })
            nlp_engine = provider.create_engine()
        except Exception:
            provider = NlpEngineProvider(nlp_configuration={
                "nlp_engine_name": "spacy",
                "models": [{"lang_code": "en", "model_name": "en_core_web_sm"}]
            })
            nlp_engine = provider.create_engine()

        registry = RecognizerRegistry()
        registry.load_predefined_recognizers(nlp_engine=nlp_engine)

        registry.add_recognizer(APIKeyRecognizer())
        registry.add_recognizer(ContextAwarePhoneRecognizer())
        registry.add_recognizer(CompositeIdentityRecognizer())

        self.analyzer = AnalyzerEngine(
            registry=registry,
            nlp_engine=nlp_engine
        )

    def analyze(self, text: str) -> List[RecognizerResult]:
        results = self.analyzer.analyze(
            text=text,
            language=self.language,
            entities=self.DEFAULT_ENTITIES,
            score_threshold=self.score_threshold
        )
        return results

    def anonymize(self, text: str, analyzer_results: List[RecognizerResult]) -> str:

        if not analyzer_results:
            return text

        anonymized = self._anonymizer.anonymize(
            text=text,
            analyzer_results=analyzer_results,
            operators={
                "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
                "PERSON": OperatorConfig("replace", {"new_value": "<PERSON>"}),
                "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL>"}),
                "PHONE_NUMBER": OperatorConfig("replace", {"new_value": "<PHONE>"}),
                "CREDIT_CARD": OperatorConfig("replace", {"new_value": "<CC_NUM>"}),
                "API_KEY_OR_INTERNAL_ID": OperatorConfig("replace", {"new_value": "<API_KEY>"}),
                "IP_ADDRESS": OperatorConfig("replace", {"new_value": "<IP_ADDR>"}),
                "COMPOSITE_IDENTITY": OperatorConfig("replace", {"new_value": "<IDENTITY>"}),
            }
        )
        return anonymized.text
