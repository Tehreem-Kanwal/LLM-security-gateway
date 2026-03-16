# 🛡️ Presidio-Based LLM Security Mini-Gateway
### CEN-451 Information Security — Assignment 2

---

## 📌 Overview

A full-stack LLM security gateway that protects AI systems from:
- Prompt injection & jailbreak attacks
- PII leakage (emails, phone numbers, API keys, student IDs, passwords)
- Composite credential leaks (username+password pairs)
- System prompt extraction attempts

**Pipeline:**
```
User Input → Injection Detection → Presidio Analyzer → Policy Decision → Output
```

---

## 🗂️ Project Structure

```
llm-security-gateway/
├── Dashboard.py              ← Streamlit frontend (run this)
├── attack_patterns.json      ← Attack pattern library
├── requirements.txt          ← All dependencies
├── src/
│   ├── main.py               ← SecurityGateway class (pipeline)
│   ├── injection_detector.py ← Weighted injection scoring
│   ├── pii_analyzer.py       ← Custom Presidio recognizers
│   └── policy_engine.py      ← Policy decision engine
├── evaluation/
│   ├── generate_tables.py    ← Generates all 5 evaluation tables
│   └── results/              ← CSV outputs of tables
└── tests/
    ├── run_tests.py           ← Automated test runner
    └── test_cases.json        ← Test case definitions
```

---

## ⚙️ Installation & Setup

### Step 1 — Create virtual environment (recommended)
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
```

### Step 2 — Install dependencies
```bash
pip install presidio-analyzer presidio-anonymizer streamlit pandas plotly tabulate
python -m spacy download en_core_web_lg
```

### Step 3 — Run the Dashboard
```bash
streamlit run Dashboard.py
```

---

## 🧪 Running Tests

```bash
# Automated test suite
python tests/run_tests.py

# Generate all 5 evaluation tables
python evaluation/generate_tables.py

# Test backend only
python src/main.py
```

---

## 📊 Evaluation Tables Generated

| Table | Description |
|-------|-------------|
| Table 1 | Scenario-Level Evaluation |
| Table 2 | Presidio Customization Validation |
| Table 3 | Performance Summary Metrics |
| Table 4 | Threshold Calibration |
| Table 5 | Latency Summary |

All saved to `evaluation/results/` as CSV files.

---

## 🔐 Custom Presidio Recognizers

| Recognizer | Entity | Example |
|---|---|---|
| PakistaniPhoneRecognizer | `PK_PHONE_NUMBER` | `+92-312-4567890` |
| APIKeyRecognizer | `API_KEY` | `sk-ABCDabcd...` |
| StudentIDRecognizer | `STUDENT_ID` | `22-BSCS-456` |
| PasswordRecognizer | `PASSWORD` | `password: secret123` |
| Context-Aware Scoring | All types | Score boosted 30% on sensitive context |
| Composite Detection | `CREDENTIAL_LEAK` | `username+password` pairs |

---

## 📋 Policy Actions

| Action | Trigger Condition |
|--------|-------------------|
| `BLOCK` | Injection score ≥ 80, OR composite credential leak |
| `FLAG` | Injection score ≥ 50 |
| `MASK` | PII detected (replaces entities with `[TYPE_REDACTED]`) |
| `ALLOW` | No threats detected |

---

## 🏛️ Bahria University Islamabad — Information Security CEN-451
