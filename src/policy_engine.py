
from enum import Enum
from typing import List
from presidio_analyzer import RecognizerResult


class PolicyDecision(Enum):
    ALLOW = "Allow"
    MASK  = "Mask"
    BLOCK = "Block"


HIGH_RISK_ENTITIES = {
    "CREDIT_CARD",
    "IBAN_CODE",
    "API_KEY_OR_INTERNAL_ID",
    "COMPOSITE_IDENTITY",
}


class PolicyEngine:


    def __init__(self, block_threshold: float = 0.75, mask_threshold: float = 0.4):
        """
        Args:
            block_threshold: injection score above which input is blocked.
            mask_threshold:  injection score above which input is masked (if not blocked).
        """
        self.block_threshold = block_threshold
        self.mask_threshold = mask_threshold

    def decide(
        self,
        injection_score: float,
        pii_results: List[RecognizerResult]
    ) -> PolicyDecision:

        # Rule 1: Block if injection score is high
        if injection_score >= self.block_threshold:
            return PolicyDecision.BLOCK

        # Rule 2: Block if high-risk PII present AND injection score is non-trivial
        high_risk_found = any(r.entity_type in HIGH_RISK_ENTITIES for r in pii_results)
        if high_risk_found and injection_score >= 0.3:
            return PolicyDecision.BLOCK

        # Rule 3: Mask if moderate injection score
        if injection_score >= self.mask_threshold:
            return PolicyDecision.MASK

        # Rule 4: Mask if any PII is detected
        if pii_results:
            return PolicyDecision.MASK

        # Rule 5: Allow clean input
        return PolicyDecision.ALLOW

    def update_thresholds(self, block_threshold: float = None, mask_threshold: float = None):
        if block_threshold is not None:
            self.block_threshold = block_threshold
        if mask_threshold is not None:
            self.mask_threshold = mask_threshold
        print(f"[PolicyEngine] Thresholds updated — Block: {self.block_threshold}, Mask: {self.mask_threshold}")
