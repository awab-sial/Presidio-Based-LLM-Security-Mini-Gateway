
import os
import torch
from transformers import pipeline, AutoTokenizer, AutoModelForSequenceClassification
from huggingface_hub import login

_HF_TOKEN = os.environ.get("HF_TOKEN")
if _HF_TOKEN:
    login(token=_HF_TOKEN, add_to_git_credential=False)


class InjectionDetector:

    BENIGN_LABEL = "BENIGN"
    INJECTION_LABEL = "INJECTION" 

    def __init__(self, model_name: str = "meta-llama/Llama-Prompt-Guard-2-86M",
                 threshold: float = 0.5):

        self.model_name = model_name
        self.threshold = threshold
        self._load_model()

    def _load_model(self):
        try:
            print(f"[InjectionDetector] Loading model: {self.model_name} ...")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(self.model_name)
            self.model.eval()
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
            self.model.to(self.device)
            self._classifier = pipeline(
                "text-classification",
                model=self.model,
                tokenizer=self.tokenizer,
                device=0 if self.device == "cuda" else -1,
                top_k=None          # return all label scores
            )
            self._available = True
            print(f"[InjectionDetector] Model loaded on {self.device}.")
        except Exception as e:
            print(f"[InjectionDetector] Model load failed: {e}")
            print("[InjectionDetector] Falling back to keyword-based heuristic scorer.")
            self._available = False

    def detect(self, text: str) -> tuple[float, str]:
        
        if self._available:
            return self._model_detect(text)
        else:
            return self._heuristic_detect(text)

    def _model_detect(self, text: str) -> tuple[float, str]:
        results = self._classifier(text[:512])

        injection_score = 0.0
        for r in results[0]:
            lbl = r["label"].upper()
            if lbl in ("1", "LABEL_1", "INJECTION", "JAILBREAK", "INDIRECT"):
                injection_score = max(injection_score, r["score"])

        # Fallback: if no positive label matched, use 1 - benign_score
        if injection_score == 0.0:
            for r in results[0]:
                lbl = r["label"].upper()
                if lbl in ("0", "LABEL_0", "BENIGN"):
                    injection_score = 1.0 - r["score"]
                    break

        label = "INJECTION" if injection_score >= self.threshold else "BENIGN"
        return injection_score, label

    def _heuristic_detect(self, text: str) -> tuple[float, str]:

        keywords = [
            "ignore previous instructions",
            "disregard your system prompt",
            "you are now",
            "pretend you are",
            "act as",
            "jailbreak",
            "dan mode",
            "do anything now",
            "forget your instructions",
            "bypass",
            "override",
            "new instructions",
            "system prompt",
            "reveal your prompt",
            "what are your instructions",
            "ignore all prior",
            "sudo",
            "admin mode",
            "developer mode",
            "unrestricted mode",
        ]
        text_lower = text.lower()
        hits = sum(1 for kw in keywords if kw in text_lower)
        score = min(hits * 0.25, 1.0)
        label = "INJECTION" if score >= self.threshold else "BENIGN"
        return score, label