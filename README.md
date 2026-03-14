# Presidio-Based LLM Security Mini-Gateway
**CEN-451 Information Security — Assignment 2**

A modular security gateway that protects LLM-based systems from prompt injection, jailbreak attacks, and sensitive data leakage using **Llama Prompt Guard 2 (86M)** and **Microsoft Presidio**.

---

## Architecture

```
User Input
    │
    ▼
┌─────────────────────┐
│  Injection Detector │  ← Llama Prompt Guard 2 (86M)
│  (injection_score)  │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│  Presidio Analyzer  │  ← Custom recognizers + context-aware scoring
│  (PII detection)    │
└────────┬────────────┘
         │
         ▼
┌─────────────────────┐
│   Policy Engine     │  ← Configurable thresholds
│  Allow/Mask/Block   │
└────────┬────────────┘
         │
         ▼
      Output
```

---

## Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/YOUR_USERNAME/llm-security-gateway.git
cd llm-security-gateway
```

### 2. Create a virtual environment (recommended)
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Download spaCy NLP model
```bash
python -m spacy download en_core_web_lg
# or smaller fallback:
python -m spacy download en_core_web_sm
```

### 5. Set up Hugging Face token (Required for Llama Prompt Guard 2)

#### Step-by-step:
1. Go to [https://huggingface.co/join](https://huggingface.co/join) and create a free account.
2. Visit [https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) and click **"Request Access"** — fill in your full legal name and organization (Bahria University).
3. Once approved (usually within a few minutes to hours), go to [https://huggingface.co/settings/tokens](https://huggingface.co/settings/tokens) and create a **Read** token.
4. Set the token in your environment:

```bash
# Windows (Command Prompt):
set HF_TOKEN=hf_your_token_here

# Windows (PowerShell):
$env:HF_TOKEN = "hf_your_token_here"

# Linux/Mac:
export HF_TOKEN=hf_your_token_here
```

Or set it in Python before running:
```python
from huggingface_hub import login
login(token="hf_your_token_here")
```

> **Note:** If access is not yet granted or you want to run without a token, the system automatically falls back to a keyword-based heuristic injection detector. All other functionality (Presidio, policy engine) works without any token.

---

## Running the Gateway

### Interactive Demo
```bash
python main.py
```

### Run Full Evaluation (All 5 Tables)
```bash
python evaluation/evaluate.py
```

---

## Configuration

Edit `config.json` to tune thresholds:

```json
{
  "model_name": "meta-llama/Llama-Prompt-Guard-2-86M",
  "injection_threshold": 0.5,
  "presidio_score_threshold": 0.4,
  "block_threshold": 0.75,
  "mask_threshold": 0.4
}
```

| Parameter | Default | Description |
|-----------|---------|-------------|
| `injection_threshold` | 0.5 | Min score to flag as injection |
| `block_threshold` | 0.75 | Score above which input is blocked |
| `mask_threshold` | 0.4 | Score above which input is masked |
| `presidio_score_threshold` | 0.4 | Min confidence for Presidio entities |

---

## Presidio Customizations

| # | Customization | Class | What It Does |
|---|--------------|-------|-------------|
| 1 | Custom Recognizer | `APIKeyRecognizer` | Detects API keys, bearer tokens, EMP-XXXX, PROJ-XXXX |
| 2 | Context-Aware Scoring | `ContextAwarePhoneRecognizer` | Boosts phone number confidence when call/contact context is present |
| 3 | Composite Entity Detection | `CompositeIdentityRecognizer` | Flags name+email or ID+DOB combinations |

---

## Project Structure

```
llm_security_gateway/
├── main.py                    # Interactive demo
├── config.json                # Configurable thresholds
├── requirements.txt
├── src/
│   ├── __init__.py
│   ├── gateway.py             # Main pipeline orchestrator
│   ├── injection_detector.py  # Llama Prompt Guard 2 wrapper
│   ├── presidio_analyzer.py   # Presidio + custom recognizers
│   └── policy_engine.py       # Policy decision logic
└── evaluation/
    ├── evaluate.py            # Structured evaluation tables
    └── evaluation_results.json
```

---

## Academic Integrity

This project was developed independently as part of CEN-451 Assignment 2 at Bahria University. All implementation decisions, design choices, and written content are the original work of the submitting student.

---

*Built with [Llama Prompt Guard 2](https://huggingface.co/meta-llama/Llama-Prompt-Guard-2-86M) by Meta and [Microsoft Presidio](https://microsoft.github.io/presidio/).*
