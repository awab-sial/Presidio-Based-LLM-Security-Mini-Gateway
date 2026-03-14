"""
gateway.py — Core LLM Security Mini-Gateway Pipeline
Presidio-Based LLM Security Gateway | CEN-451 Assignment 2
"""

import time
import json
from typing import Optional
from src.injection_detector import InjectionDetector
from src.presidio_analyzer import PresidioAnalyzerWrapper
from src.policy_engine import PolicyEngine, PolicyDecision


class LLMSecurityGateway:

    def __init__(self, config_path: Optional[str] = None):

        self.config = self._load_config(config_path)

        self.injection_detector = InjectionDetector(
            model_name=self.config.get("model_name", "meta-llama/Llama-Prompt-Guard-2-86M"),
            threshold=self.config.get("injection_threshold", 0.5)
        )

        self.presidio_analyzer = PresidioAnalyzerWrapper(
            score_threshold=self.config.get("presidio_score_threshold", 0.4)
        )

        self.policy_engine = PolicyEngine(
            block_threshold=self.config.get("block_threshold", 0.75),
            mask_threshold=self.config.get("mask_threshold", 0.4)
        )

        self.metrics = {
            "total_requests": 0,
            "blocked": 0,
            "masked": 0,
            "allowed": 0,
            "total_latency_ms": 0.0
        }

    def _load_config(self, config_path: Optional[str]) -> dict:
        defaults = {
            "model_name": "meta-llama/Llama-Prompt-Guard-2-86M",
            "injection_threshold": 0.5,
            "presidio_score_threshold": 0.4,
            "block_threshold": 0.75,
            "mask_threshold": 0.4
        }
        if config_path:
            try:
                with open(config_path, "r") as f:
                    user_config = json.load(f)
                    defaults.update(user_config)
            except (FileNotFoundError, json.JSONDecodeError) as e:
                print(f"[WARNING] Could not load config: {e}. Using defaults.")
        return defaults

    def process(self, user_input: str) -> dict:

        start_time = time.perf_counter()
        self.metrics["total_requests"] += 1

        # Step 1: Injection Detection
        injection_score, injection_label = self.injection_detector.detect(user_input)

        # Step 2: Presidio PII Detection
        pii_results = self.presidio_analyzer.analyze(user_input)

        # Step 3: Policy Decision
        decision = self.policy_engine.decide(injection_score, pii_results)

        # Step 4: Apply Decision
        if decision == PolicyDecision.BLOCK:
            output = "[BLOCKED] This request was flagged as a potential prompt injection or jailbreak attempt."
            self.metrics["blocked"] += 1
        elif decision == PolicyDecision.MASK:
            output = self.presidio_analyzer.anonymize(user_input, pii_results)
            self.metrics["masked"] += 1
        else:
            output = user_input
            self.metrics["allowed"] += 1

        end_time = time.perf_counter()
        latency_ms = (end_time - start_time) * 1000
        self.metrics["total_latency_ms"] += latency_ms

        return {
            "decision": decision.value,
            "output": output,
            "injection_score": round(injection_score, 4),
            "injection_label": injection_label,
            "pii_entities": [
                {
                    "entity_type": r.entity_type,
                    "score": round(r.score, 4),
                    "start": r.start,
                    "end": r.end
                }
                for r in pii_results
            ],
            "latency_ms": round(latency_ms, 3)
        }

    def get_summary_metrics(self) -> dict:
        total = self.metrics["total_requests"]
        avg_latency = (
            self.metrics["total_latency_ms"] / total if total > 0 else 0.0
        )
        return {
            "total_requests": total,
            "blocked": self.metrics["blocked"],
            "masked": self.metrics["masked"],
            "allowed": self.metrics["allowed"],
            "block_rate": round(self.metrics["blocked"] / total, 4) if total > 0 else 0,
            "mask_rate": round(self.metrics["masked"] / total, 4) if total > 0 else 0,
            "avg_latency_ms": round(avg_latency, 3)
        }
