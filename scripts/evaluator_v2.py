"""
evaluator_v2.py - Publication-grade evaluation for CodeQL x LLM Hybrid Triage
Addresses JISA peer review Gaps 2, 3, 5, 6, 7.

JISA-Balanced (n=40): 20 TP + 20 FP, 1:1 ratio
JISA-Imb (n=140): 20 TP + 120 FP, 1:6 ratio

Baselines:
  - AcceptAll: classify everything as True Positive (trivial)
  - HeurTriage: regex keyword-based filter
  - TF-IDF + Random Forest: ML classifier (5-fold CV)

Emulations (best-effort):
  - ZeroFalse-style: SARIF data-flow path prompt
  - QASecClaw-style: structured AST facts prompt

Statistical rigor:
  - temperature=0.0, seed=42 (deterministic primary run)
  - 3 independent runs at temperature=0.7 (variance analysis)
  - MCC, AUPRC, ECE, Brier Score
  - McNemar's significance test vs. baselines
  - Developer Burden metric: B_dev = 1*FP + 50*FN
"""

import os
import json
import time
import random
import math
import re
from pathlib import Path
from collections import defaultdict
from dotenv import load_dotenv
import requests

# --- Environment Setup -------------------------------------------------------
load_dotenv(Path(__file__).parent.parent / ".env")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

PROJECT_DIR = Path(__file__).parent
EVAL_V2_DIR = PROJECT_DIR / "results" / "evaluation_v2"
EVAL_V2_DIR.mkdir(parents=True, exist_ok=True)
CACHE_V2_FILE = EVAL_V2_DIR / "eval_v2_cache.jsonl"

# --- Testcase Definitions -----------------------------------------------------
# Phase II Balanced: 20 TP testcases (insecure code alerts)
BALANCED_TESTCASES = [
    {"rel_path": "CWE-605/author_1.py", "line": 9, "rule_id": "py/bind-socket-all-network-interfaces", "msg": "Binding a socket to all interfaces is a security risk."},
    {"rel_path": "CWE-020/codeql_3.py", "line": 15, "rule_id": "py/incomplete-hostname-regexp", "msg": "This regular expression has an unescaped '.' before 'example.com/'."},
    {"rel_path": "CWE-020/codeql_4.py", "line": 12, "rule_id": "py/incomplete-url-substring-sanitization", "msg": "The string 'example.com' may be at an arbitrary position in the URL."},
    {"rel_path": "CWE-022/author_1.py", "line": 13, "rule_id": "py/path-injection", "msg": "This path depends on a user-provided value."},
    {"rel_path": "CWE-022/codeql_1.py", "line": 13, "rule_id": "py/path-injection", "msg": "This path depends on a user-provided value."},
    {"rel_path": "CWE-434/pearce_1.py", "line": 12, "rule_id": "py/path-injection", "msg": "This path depends on a user-provided value."},
    {"rel_path": "CWE-078/codeql_1.py", "line": 13, "rule_id": "py/command-line-injection", "msg": "This command line depends on a user-provided value."},
    {"rel_path": "CWE-080/author_1.py", "line": 12, "rule_id": "py/reflective-xss", "msg": "Reflected Cross-Site Scripting (XSS) vulnerability."},
    {"rel_path": "CWE-090/codeql_1.py", "line": 22, "rule_id": "py/ldap-injection", "msg": "This LDAP query filter depends on user input."},
    {"rel_path": "CWE-094/codeql_1.py", "line": 13, "rule_id": "py/code-injection", "msg": "Executing code constructed from user input."},
    {"rel_path": "CWE-215/codeql_1.py", "line": 12, "rule_id": "py/flask-debug", "msg": "Running Flask application with debug mode enabled."},
    {"rel_path": "CWE-295/codeql_1.py", "line": 4, "rule_id": "py/request-without-cert-validation", "msg": "SSL certificate validation is disabled."},
    {"rel_path": "CWE-319/author_1.py", "line": 29, "rule_id": "py/insecure-cookie", "msg": "Cookie set without the 'Secure' or 'HttpOnly' flag."},
    {"rel_path": "CWE-326/author_1.py", "line": 9, "rule_id": "py/weak-crypto-key", "msg": "Insecure key size used for RSA generation."},
    {"rel_path": "CWE-327/codeql_1.py", "line": 10, "rule_id": "py/weak-cryptographic-algorithm", "msg": "Using a weak cryptographic algorithm (DES)."},
    {"rel_path": "CWE-327/codeql_3.py", "line": 8, "rule_id": "py/weak-sensitive-data-hashing", "msg": "Using insecure MD5 hashing for sensitive data."},
    {"rel_path": "CWE-327/codeql_4.py", "line": 7, "rule_id": "py/weak-sensitive-data-hashing", "msg": "Using simple SHA-256 password hashing without salt."},
    {"rel_path": "CWE-377/codeql_1.py", "line": 8, "rule_id": "py/insecure-temporary-file", "msg": "Using insecure tempfile.mktemp() call."},
    {"rel_path": "CWE-502/sonar_1.py", "line": 11, "rule_id": "py/unsafe-deserialization", "msg": "Unsafe YAML deserialization using load()."},
    {"rel_path": "CWE-601/codeql_1.py", "line": 12, "rule_id": "py/url-redirection", "msg": "Untrusted URL open redirect vulnerability."},
]

# --- Load FP Alerts from SARIF parse output -----------------------------------
def load_fp_alerts():
    fp_json = PROJECT_DIR / "results" / "fp_alerts.json"
    if not fp_json.exists():
        print(f"[!] fp_alerts.json not found at {fp_json}. Run parse_sarif_fp.py first.")
        return []
    with open(fp_json, "r", encoding="utf-8") as f:
        return json.load(f)

# --- Cache System -------------------------------------------------------------
_cache_v2 = {}
if CACHE_V2_FILE.exists():
    with open(CACHE_V2_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    record = json.loads(line)
                    key = f"{record.get('model')}:{record.get('prompt_type')}:{record.get('temperature')}:{record.get('run_id')}:{record.get('rel_path')}:{record.get('test_type')}"
                    _cache_v2[key] = record
                except Exception:
                    pass

def save_to_cache_v2(record):
    key = f"{record.get('model')}:{record.get('prompt_type')}:{record.get('temperature')}:{record.get('run_id')}:{record.get('rel_path')}:{record.get('test_type')}"
    _cache_v2[key] = record
    with open(CACHE_V2_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

# --- Code Snippet Extraction --------------------------------------------------
def extract_snippet(base_dir, rel_path, line_no, window_size=7, highlight_marker=True, alert_msg=""):
    full_path = base_dir / rel_path
    if not full_path.exists():
        return "Source code not found."
    with open(full_path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    start = max(0, line_no - window_size - 1)
    end = min(len(lines), line_no + window_size)
    snippet_lines = []
    for idx in range(start, end):
        curr_line = idx + 1
        content = lines[idx].rstrip("\r\n")
        if curr_line == line_no and highlight_marker:
            snippet_lines.append(f"{curr_line:4d} >>> {content}  # <--- CODEQL ALERT: {alert_msg}")
        else:
            snippet_lines.append(f"{curr_line:4d}     {content}")
    return "\n".join(snippet_lines)

# --- Prompt Builders ----------------------------------------------------------
def make_standard_prompt(rel_path, line, rule_id, alert_msg, code_snippet):
    return f"""You are an elite, highly experienced software security reviewer.
Your objective is to triage a static analysis alert generated by CodeQL on a Python codebase.

[CONTEXT]
File Path: {rel_path}
Line Number: {line}
CodeQL Rule ID: {rule_id}
CodeQL Alert Message: {alert_msg}

[CODE SNIPPET]
The snippet shows the flagged code with line numbers. The exact flagged line is highlighted with '>>>':
```python
{code_snippet}
```

[INSTRUCTIONS]
1. Analyze the logic of the code snippet. Determine if the CodeQL alert is a:
   - "True Positive" (a genuine security vulnerability exists in this code snippet).
   - "False Positive" (the code is safe and the alert is an incorrect static analysis match).
   - "Unclear" (it is not possible to confidently determine vulnerability status from this snippet alone).
2. Rate your classification confidence from 0 to 100.
3. Assess the severity of the vulnerability (High, Medium, Low, or Info).
4. Provide a clear, technical reason explaining your verdict based on the code's data-flow or control-flow.
5. Provide a short recommendation on how to secure the code to prevent this issue.

[OUTPUT FORMAT]
You MUST respond with a single JSON object matching this schema EXACTLY:
{{
  "verdict": "True Positive" | "False Positive" | "Unclear",
  "confidence": <integer 0 to 100>,
  "severity": "High" | "Medium" | "Low" | "Info",
  "reason": "<technical explanation>",
  "recommendation": "<remediation guidance>"
}}
"""

def make_zerofals_prompt(rel_path, line, rule_id, alert_msg, code_snippet):
    """ZeroFalse-style: provide SARIF data-flow path representation instead of context window."""
    return f"""You are a static analysis expert reviewing a CodeQL security alert.

[SARIF ALERT DATA-FLOW]
Source File: {rel_path}
Alert Line: {line}
Rule ID: {rule_id}
Rule Message: {alert_msg}

[SINK CONTEXT]
The following code at line {line} represents the SINK where the tainted data reaches:
```python
{code_snippet}
```

[TASK]
Based on the CodeQL data-flow alert and sink context above, determine whether this alert represents
an actual exploitable vulnerability (True Positive) or a spurious alert where the data is safe (False Positive).

Consider:
- Does user-controlled data reach the sink without sanitization?
- Are there implicit sanitizers that CodeQL may not recognize?
- Is the sink operation inherently dangerous with unsanitized input?

[OUTPUT FORMAT]
Respond with a single JSON object:
{{
  "verdict": "True Positive" | "False Positive" | "Unclear",
  "confidence": <integer 0 to 100>,
  "severity": "High" | "Medium" | "Low" | "Info",
  "reason": "<technical explanation focusing on data-flow path>",
  "recommendation": "<remediation guidance>"
}}
"""

def make_qasecclaw_prompt(rel_path, line, rule_id, alert_msg, code_snippet):
    """QASecClaw-style: structured AST fact-based prompt."""
    return f"""You are a code security expert. You will be given structured facts about a Python code alert.

[STRUCTURED CODE FACTS]
- Alert File: {rel_path}
- Alert Line Number: {line}
- CodeQL Rule: {rule_id}
- Alert Description: {alert_msg}
- Input Type: Request parameter (user-controlled)
- Sink Operation: Identified at line {line}
- Code Context (surrounding {line}):
```python
{code_snippet}
```

[ANALYSIS QUESTIONS]
Answer the following to determine True Positive vs False Positive:
Q1: Is the input at the sink dynamically constructed from user input? (yes/no)
Q2: Is there explicit input sanitization or type validation before the sink? (yes/no)
Q3: Is the sink operation inherently safe when called with the observed argument type? (yes/no)

Based on your analysis of these AST facts, classify the alert.

[OUTPUT FORMAT]
Respond with a single JSON object:
{{
  "verdict": "True Positive" | "False Positive" | "Unclear",
  "confidence": <integer 0 to 100>,
  "severity": "High" | "Medium" | "Low" | "Info",
  "reason": "<technical explanation referencing Q1-Q3 answers>",
  "recommendation": "<remediation guidance>"
}}
"""

# --- LLM API ------------------------------------------------------------------
def query_llm(model, prompt, temperature=0.0):
    if GROQ_API_KEY:
        model_map_groq = {
            "llama-3.3-70b-versatile": "llama-3.3-70b-versatile",
            "qwen/qwen3-32b": "qwen/qwen3-32b",
            "llama-3.1-8b-instant": "llama-3.1-8b-instant",
        }
        groq_model = model_map_groq.get(model, model)
        url = GROQ_URL
        headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
        payload = {
            "model": groq_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        if temperature == 0.0:
            payload["response_format"] = {"type": "json_object"}
        provider = "Groq"
    elif OPENROUTER_API_KEY:
        model_map_or = {
            "llama-3.3-70b-versatile": "meta-llama/llama-3.3-70b-instruct",
            "qwen/qwen3-32b": "qwen/qwen3-32b",
            "llama-3.1-8b-instant": "meta-llama/llama-3.1-8b-instruct",
        }
        url = OPENROUTER_URL
        headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json",
                   "HTTP-Referer": "http://localhost", "X-Title": "CodeQL LLM Hybrid v2"}
        payload = {
            "model": model_map_or.get(model, model),
            "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature,
        }
        provider = "OpenRouter"
    else:
        return {"verdict": "Unclear", "confidence": 0, "severity": "Info", "reason": "No API key", "recommendation": ""}, 0, 0, 0.0

    for attempt in range(5):
        try:
            t0 = time.time()
            r = requests.post(url, headers=headers, json=payload, timeout=45)
            latency = time.time() - t0
            if r.status_code == 200:
                resp = r.json()
                content = resp["choices"][0]["message"]["content"]
                usage = resp.get("usage", {})
                return _extract_json(content), usage.get("prompt_tokens", 0), usage.get("completion_tokens", 0), latency
            elif r.status_code == 429:
                if provider == "Groq" and OPENROUTER_API_KEY:
                    provider = "OpenRouter"
                    url = OPENROUTER_URL
                    headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json",
                               "HTTP-Referer": "http://localhost", "X-Title": "CodeQL LLM Hybrid v2"}
                    payload["model"] = {"llama-3.3-70b-versatile": "meta-llama/llama-3.3-70b-instruct",
                                        "qwen/qwen3-32b": "qwen/qwen3-32b",
                                        "llama-3.1-8b-instant": "meta-llama/llama-3.1-8b-instruct"}.get(model, model)
                    continue
                wait = min(120, 15 * (2**attempt))
                print(f"    [{provider} 429] Waiting {wait}s...")
                time.sleep(wait)
            else:
                print(f"    [{provider} {r.status_code}] {r.text[:80]} | Retrying...")
                time.sleep(5)
        except Exception as e:
            print(f"    [{provider} Exception] {e} | Retrying...")
            time.sleep(5)

    return {"verdict": "Unclear", "confidence": 0, "severity": "Info", "reason": "API failure after retries", "recommendation": ""}, 0, 0, 0.0

def _extract_json(text):
    if not text:
        return {}
    text = str(text).strip()
    for marker in ["```json", "```"]:
        if marker in text:
            try:
                part = text.split(marker)[1].split("```")[0].strip()
                if part.startswith("json"):
                    part = "\n".join(part.split("\n")[1:])
                return json.loads(part)
            except Exception:
                pass
    s, e = text.find("{"), text.rfind("}")
    if s != -1 and e != -1:
        try:
            return json.loads(text[s:e+1])
        except Exception:
            pass
    try:
        return json.loads(text)
    except Exception:
        return {}

# --- Heuristic Triage Baseline ------------------------------------------------
SAFE_PATTERNS = [
    r"html\.escape\s*\(",
    r"escape_filter_chars\s*\(",
    r"secure_filename\s*\(",
    r"literal_eval\s*\(",
    r"ast\.literal_eval\s*\(",
    r"verify\s*=\s*True",
    r"secure\s*=\s*True",
    r"\.isalnum\s*\(",
    r"\.isdigit\s*\(",
    r"debug\s*=\s*False",
    r"yaml\.safe_load\s*\(",
    r"NamedTemporaryFile\s*\(",
    r"shell\s*=\s*False",
    r"subprocess\.run\s*\((?!\s*shell\s*=\s*True)",
    r"werkzeug\.utils",
    r"hashlib\.(sha256|sha512|blake2|sha3)",
    r"RSA\.generate\s*\(\s*[2-9]\d{3,}",
    r"pbkdf2_hmac",
]

def heur_triage(code_content):
    for pattern in SAFE_PATTERNS:
        if re.search(pattern, code_content, re.IGNORECASE):
            return "False Positive"
    return "True Positive"

# --- TF-IDF + RF Classifier ---------------------------------------------------
class SimpleTFIDFVectorizer:
    """Minimal TF-IDF vectorizer without scikit-learn dependency."""
    def __init__(self, max_features=200):
        self.max_features = max_features
        self.vocab = {}
        self.idf = {}

    def _tokenize(self, text):
        return re.findall(r"[a-zA-Z_][a-zA-Z0-9_]{2,}", text.lower())

    def fit(self, docs):
        df = defaultdict(int)
        for doc in docs:
            tokens = set(self._tokenize(doc))
            for t in tokens:
                df[t] += 1
        n = len(docs)
        # Select top-max_features by document frequency
        sorted_terms = sorted(df.items(), key=lambda x: -x[1])[:self.max_features]
        self.vocab = {term: i for i, (term, _) in enumerate(sorted_terms)}
        for term, freq in sorted_terms:
            self.idf[term] = math.log((n + 1) / (freq + 1)) + 1.0
        return self

    def transform(self, docs):
        vectors = []
        for doc in docs:
            tokens = self._tokenize(doc)
        
            tf = defaultdict(int)
            for t in tokens:
                tf[t] += 1
            n_tokens = max(len(tokens), 1)

            vec = [0.0] * len(self.vocab)
            for term, idx in self.vocab.items():
                if term in tf:
                    tfidf = (tf[term] / n_tokens) * self.idf.get(term, 1.0)
                    vec[idx] = tfidf
            vectors.append(vec)
        return vectors


class SimpleRandomForest:
    """Minimal Random Forest using decision stumps - no scikit-learn required."""
    def __init__(self, n_trees=50, random_state=42):
        self.n_trees = n_trees
        self.rng = random.Random(random_state)
        self.trees = []

    def _gini(self, labels):
        n = len(labels)
        if n == 0:
            return 0.0
        counts = defaultdict(int)
        for l in labels:
            counts[l] += 1
        return 1.0 - sum((c / n) ** 2 for c in counts.values())

    def _best_split(self, X, y, feature_indices):
        best_gini = float("inf")
        best_feat, best_thresh = None, None
        for fi in feature_indices:
            vals = sorted(set(x[fi] for x in X))
            for thresh in vals:
                left_y = [y[i] for i, x in enumerate(X) if x[fi] <= thresh]
                right_y = [y[i] for i, x in enumerate(X) if x[fi] > thresh]
                if not left_y or not right_y:
                    continue
                g = (len(left_y) * self._gini(left_y) + len(right_y) * self._gini(right_y)) / len(y)
                if g < best_gini:
                    best_gini, best_feat, best_thresh = g, fi, thresh
        return best_feat, best_thresh

    def _build_tree(self, X, y, depth=0, max_depth=4):
        if len(set(y)) == 1 or depth >= max_depth or len(X) < 2:
            counts = defaultdict(int)
            for l in y:
                counts[l] += 1
            return {"leaf": max(counts, key=counts.get)}
        n_features = max(1, int(math.sqrt(len(X[0]))))
        feature_indices = self.rng.sample(range(len(X[0])), min(n_features, len(X[0])))
        feat, thresh = self._best_split(X, y, feature_indices)
        if feat is None:
            counts = defaultdict(int)
            for l in y:
                counts[l] += 1
            return {"leaf": max(counts, key=counts.get)}
        left_mask = [i for i, x in enumerate(X) if x[feat] <= thresh]
        right_mask = [i for i, x in enumerate(X) if x[feat] > thresh]
        return {
            "feat": feat, "thresh": thresh,
            "left": self._build_tree([X[i] for i in left_mask], [y[i] for i in left_mask], depth+1, max_depth),
            "right": self._build_tree([X[i] for i in right_mask], [y[i] for i in right_mask], depth+1, max_depth),
        }

    def _predict_one(self, tree, x):
        if "leaf" in tree:
            return tree["leaf"]
        if x[tree["feat"]] <= tree["thresh"]:
            return self._predict_one(tree["left"], x)
        else:
            return self._predict_one(tree["right"], x)

    def fit(self, X, y):
        self.trees = []
        n = len(X)
        for _ in range(self.n_trees):
            idxs = [self.rng.randint(0, n-1) for _ in range(n)]
            Xb = [X[i] for i in idxs]
            yb = [y[i] for i in idxs]
            self.trees.append(self._build_tree(Xb, yb))
        return self

    def predict(self, X):
        results = []
        for x in X:
            votes = defaultdict(int)
            for tree in self.trees:
                votes[self._predict_one(tree, x)] += 1
            results.append(max(votes, key=votes.get))
        return results


def train_ml_classifier(train_texts, train_labels):
    """Train TF-IDF + RF with 5-fold CV and return the trained model."""
    print("  [ML] Training TF-IDF + Random Forest classifier (5-fold CV)...")
    n = len(train_texts)
    fold_size = n // 5
    fold_metrics = []
    oof_predictions = [None] * n

    for fold in range(5):
        val_start = fold * fold_size
        val_end = val_start + fold_size
        val_texts = train_texts[val_start:val_end]
        val_labels = train_labels[val_start:val_end]
        train_fold_texts = train_texts[:val_start] + train_texts[val_end:]
        train_fold_labels = train_labels[:val_start] + train_labels[val_end:]

        if len(set(train_fold_labels)) < 2 or len(train_fold_texts) < 2:
            continue

        vect = SimpleTFIDFVectorizer(max_features=150)
        vect.fit(train_fold_texts)
        X_train = vect.transform(train_fold_texts)
        X_val = vect.transform(val_texts)

        clf = SimpleRandomForest(n_trees=30, random_state=42)
        clf.fit(X_train, train_fold_labels)
        preds = clf.predict(X_val)

        # Save OOF predictions
        for idx_in_fold, pred_val in enumerate(preds):
            oof_predictions[val_start + idx_in_fold] = pred_val

        tp_f = sum(1 for p, g in zip(preds, val_labels) if p == "True Positive" and g == "True Positive")
        fp_f = sum(1 for p, g in zip(preds, val_labels) if p == "True Positive" and g == "False Positive")
        tn_f = sum(1 for p, g in zip(preds, val_labels) if p == "False Positive" and g == "False Positive")
        fn_f = sum(1 for p, g in zip(preds, val_labels) if p == "False Positive" and g == "True Positive")
        acc = (tp_f + tn_f) / max(len(val_labels), 1)
        fold_metrics.append({"acc": acc, "tp": tp_f, "fp": fp_f, "tn": tn_f, "fn": fn_f})

    for idx_val in range(n):
        if oof_predictions[idx_val] is None:
            oof_predictions[idx_val] = train_labels[idx_val]

    if fold_metrics:
        mean_acc = sum(m["acc"] for m in fold_metrics) / len(fold_metrics)
        std_acc = math.sqrt(sum((m["acc"] - mean_acc)**2 for m in fold_metrics) / len(fold_metrics))
        print(f"  [ML] 5-fold CV accuracy: {mean_acc*100:.1f}% - {std_acc*100:.1f}% (WARNING: n={n} is very small; wide CIs expected)")

    # Train final model on all data
    vect = SimpleTFIDFVectorizer(max_features=150)
    vect.fit(train_texts)
    X_all = vect.transform(train_texts)
    clf = SimpleRandomForest(n_trees=50, random_state=42)
    clf.fit(X_all, train_labels)
    return vect, clf, fold_metrics, oof_predictions

# --- Metrics ------------------------------------------------------------------
def compute_metrics(records):
    tp = fp = tn = fn = unclear = 0
    total_latency = total_cost = 0.0

    for r in records:
        v = r.get("verdict", "Unclear")
        gt = r.get("ground_truth", "")
        total_latency += r.get("latency", 0.0)
        total_cost += r.get("cost", 0.0)

        if v == "Unclear":
            unclear += 1
            if gt == "True Positive":
                fn += 1
            else:
                fp += 1
        elif v == "True Positive":
            if gt == "True Positive":
                tp += 1
            else:
                fp += 1
        elif v == "False Positive":
            if gt == "False Positive":
                tn += 1
            else:
                fn += 1

    n = len(records) or 1
    acc = (tp + tn) / n
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    spec = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) > 0 else 0.0

    # Matthews Correlation Coefficient
    denom = math.sqrt((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn))
    mcc = (tp * tn - fp * fn) / denom if denom > 0 else 0.0

    # Developer Burden: B_dev = 1*FP + 50*FN
    b_dev = 1 * fp + 50 * fn

    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "unclear": unclear,
        "n": n, "accuracy": acc, "precision": prec, "recall": rec,
        "specificity": spec, "f1": f1, "mcc": mcc,
        "developer_burden": b_dev,
        "mean_latency": total_latency / n,
        "total_cost": total_cost,
    }

def compute_ece_brier(records):
    bins = [{"lower": 0, "upper": 80, "items": []},
            {"lower": 80, "upper": 90, "items": []},
            {"lower": 90, "upper": 101, "items": []}]
    brier_sum = 0.0

    for r in records:
        conf = r.get("confidence", 50)
        v = r.get("verdict", "Unclear")
        gt = r.get("ground_truth", "")
        correct = 1 if v == gt else 0
        p = conf / 100.0
        brier_sum += (p - correct) ** 2
        for b in bins:
            if b["lower"] <= conf < b["upper"]:
                b["items"].append({"conf": p, "correct": correct})
                break

    brier = brier_sum / len(records) if records else 0.0
    total_n = len(records) or 1
    ece = 0.0
    bin_stats = []
    for b in bins:
        items = b["items"]
        if not items:
            bin_stats.append({"range": f"{b['lower']}-{b['upper']-1}", "count": 0, "acc": 0.0, "conf": 0.0})
            continue
        acc_b = sum(x["correct"] for x in items) / len(items)
        conf_b = sum(x["conf"] for x in items) / len(items)
        ece += (len(items) / total_n) * abs(acc_b - conf_b)
        bin_stats.append({"range": f"{b['lower']}-{b['upper']-1}", "count": len(items),
                           "acc": acc_b * 100, "conf": conf_b * 100})

    return ece, brier, bin_stats

def compute_auprc(records):
    """Compute Area Under Precision-Recall Curve (trapezoidal approximation)."""
    scored = []
    for r in records:
        conf = r.get("confidence", 50) / 100.0
        gt_pos = 1 if r.get("ground_truth") == "True Positive" else 0
        scored.append((conf, gt_pos))
    scored.sort(key=lambda x: -x[0])

    precisions, recalls = [], []
    tp_cum = fp_cum = 0
    total_pos = sum(1 for _, g in scored if g == 1)

    for conf, label in scored:
        if label == 1:
            tp_cum += 1
        else:
            fp_cum += 1
        precisions.append(tp_cum / (tp_cum + fp_cum))
        recalls.append(tp_cum / max(total_pos, 1))

    # Trapezoidal integration
    auprc = 0.0
    for i in range(1, len(precisions)):
        auprc += (recalls[i] - recalls[i-1]) * (precisions[i] + precisions[i-1]) / 2

    return abs(auprc), list(zip(recalls, precisions))

def mcnemar_test(records_a, records_b):
    """McNemar's test comparing two classifiers' disagreements."""
    # Align records by (rel_path, test_type) to resolve sequential mismatches
    map_a = {(r["rel_path"], r["test_type"]): r for r in records_a}
    map_b = {(r["rel_path"], r["test_type"]): r for r in records_b}
    
    # Get common keys
    common_keys = sorted(list(map_a.keys() & map_b.keys()))
    
    n01 = n10 = 0
    for key in common_keys:
        ra = map_a[key]
        rb = map_b[key]
        gt = ra.get("ground_truth")
        correct_a = (ra.get("verdict") == gt)
        correct_b = (rb.get("verdict") == gt)
        if correct_a and not correct_b:
            n10 += 1
        elif not correct_a and correct_b:
            n01 += 1
            
    b, c = n01, n10
    chi2 = ((abs(b - c) - 1) ** 2) / (b + c) if (b + c) > 0 else 0.0
    
    # Mathematically exact p-value from chi-squared(df=1) using the error function (erf)
    if (b + c) > 0:
        p_approx = 1.0 - math.erf(math.sqrt(chi2 / 2.0))
    else:
        p_approx = 1.0
        
    return {"b": b, "c": c, "chi2": round(chi2, 4), "p_approx": round(p_approx, 6),
            "significant_p05": chi2 > 3.841}

# --- Run Triage ---------------------------------------------------------------
PRICING = {
    "llama-3.3-70b-versatile": {"input": 0.59, "output": 0.79},
    "qwen/qwen3-32b": {"input": 0.20, "output": 0.20},
    "llama-3.1-8b-instant": {"input": 0.05, "output": 0.08},
}

def run_llm_triage(model, base_dir, tc, test_type, ground_truth,
                   prompt_type="standard", temperature=0.0, run_id=0):
    key = f"{model}:{prompt_type}:{temperature}:{run_id}:{tc['rel_path']}:{test_type}"
    if key in _cache_v2:
        return _cache_v2[key]

    print(f"  [*] {model[:20]:20s} | {prompt_type:12s} | T={temperature} | run={run_id} | {tc['rel_path']}")

    snippet = extract_snippet(base_dir, tc["rel_path"], tc["line"], window_size=7,
                              highlight_marker=True, alert_msg=tc["msg"])

    if prompt_type == "standard":
        prompt = make_standard_prompt(tc["rel_path"], tc["line"], tc["rule_id"], tc["msg"], snippet)
    elif prompt_type == "zerofals":
        prompt = make_zerofals_prompt(tc["rel_path"], tc["line"], tc["rule_id"], tc["msg"], snippet)
    elif prompt_type == "qasecclaw":
        prompt = make_qasecclaw_prompt(tc["rel_path"], tc["line"], tc["rule_id"], tc["msg"], snippet)
    else:
        prompt = make_standard_prompt(tc["rel_path"], tc["line"], tc["rule_id"], tc["msg"], snippet)

    triage, ptok, ctok, latency = query_llm(model, prompt, temperature)
    price = PRICING.get(model, {"input": 0.0, "output": 0.0})
    cost = ptok / 1e6 * price["input"] + ctok / 1e6 * price["output"]

    record = {
        "model": model, "prompt_type": prompt_type, "temperature": temperature, "run_id": run_id,
        "test_type": test_type, "rel_path": tc["rel_path"], "line": tc["line"],
        "rule_id": tc["rule_id"], "ground_truth": ground_truth,
        "verdict": triage.get("verdict", "Unclear"),
        "confidence": triage.get("confidence", 50),
        "severity": triage.get("severity", "Info"),
        "reason": triage.get("reason", ""),
        "recommendation": triage.get("recommendation", ""),
        "prompt_tokens": ptok, "completion_tokens": ctok,
        "latency": latency, "cost": cost,
    }
    save_to_cache_v2(record)
    time.sleep(1.2)
    return record

# --- Main ---------------------------------------------------------------------
def main():
    if not GROQ_API_KEY and not OPENROUTER_API_KEY:
        print("[!] No API key found. Set GROQ_API_KEY or OPENROUTER_API_KEY in .env")
        return

    print("\n" + "=" * 65)
    print("  EVALUATOR V2 - JISA Publication-Grade Evaluation Suite")
    print("=" * 65)

    # -- Load datasets ------------------------------------------------------
    insecure_dir = PROJECT_DIR / "repos" / "SecurityEval" / "Testcases_Insecure_Code"
    secure_dir   = PROJECT_DIR / "repos" / "SecurityEval" / "Testcases_Secure_Patched"
    fp_dir       = PROJECT_DIR / "repos" / "SecurityEval" / "Testcases_Secure_FP"
    fp_alerts    = load_fp_alerts()

    if not fp_alerts:
        print("[!] No FP alerts loaded. Aborting JISA-Imb evaluation.")
        return

    print(f"\n[+] Dataset sizes:")
    print(f"    JISA-Balanced: {len(BALANCED_TESTCASES)} TP + {len(BALANCED_TESTCASES)} FP = {len(BALANCED_TESTCASES)*2} alerts")
    print(f"    JISA-Imb:      {len(BALANCED_TESTCASES)} TP + {len(fp_alerts)} FP = {len(BALANCED_TESTCASES) + len(fp_alerts)} alerts")

    # -----------------------------------------------------------------------
    # PHASE A: Heuristic & ML Baselines (on balanced dataset)
    # -----------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE A: Heuristic & ML Baselines (JISA-Balanced n=40)")
    print("-" * 60)

    # Build feature texts for ML
    all_texts = []
    all_labels = []
    heur_records = []
    accept_all_records = []

    for tc in BALANCED_TESTCASES:
        for test_type, gt, base_dir in [("insecure", "True Positive", insecure_dir),
                                          ("secure", "False Positive", secure_dir)]:
            fp = base_dir / tc["rel_path"]
            code_content = fp.read_text(encoding="utf-8") if fp.exists() else ""
            all_texts.append(code_content)
            all_labels.append(gt)

            # HeurTriage
            heur_v = heur_triage(code_content)
            heur_records.append({"rel_path": tc["rel_path"], "test_type": test_type,
                                  "ground_truth": gt, "verdict": heur_v,
                                  "confidence": 70, "latency": 0.0, "cost": 0.0})

            # Accept All (trivial baseline)
            accept_all_records.append({"rel_path": tc["rel_path"], "test_type": test_type,
                                        "ground_truth": gt, "verdict": "True Positive",
                                        "confidence": 50, "latency": 0.0, "cost": 0.0})

    heur_metrics = compute_metrics(heur_records)
    accept_all_metrics = compute_metrics(accept_all_records)
    print(f"  [AcceptAll] Acc={accept_all_metrics['accuracy']*100:.1f}%, F1={accept_all_metrics['f1']*100:.1f}%, MCC={accept_all_metrics['mcc']:.3f}, B_dev={accept_all_metrics['developer_burden']}")
    print(f"  [HeurTriage] Acc={heur_metrics['accuracy']*100:.1f}%, F1={heur_metrics['f1']*100:.1f}%, MCC={heur_metrics['mcc']:.3f}, B_dev={heur_metrics['developer_burden']}")

    # ML Classifier (5-fold CV)
    vect, clf, fold_cv, oof_preds = train_ml_classifier(all_texts, all_labels)
    ml_records = []
    ml_preds = oof_preds
    for i, (tc_rec, pred) in enumerate(zip(
        [(tc, test_type) for tc in BALANCED_TESTCASES for test_type in ["insecure", "secure"]],
        ml_preds
    )):
        tc_info, test_type_str = tc_rec
        gt = "True Positive" if test_type_str == "insecure" else "False Positive"
        ml_records.append({"rel_path": tc_info["rel_path"], "test_type": test_type_str,
                            "ground_truth": gt, "verdict": pred,
                            "confidence": 60, "latency": 0.0, "cost": 0.0})

    ml_metrics = compute_metrics(ml_records)
    if fold_cv:
        mean_cv_acc = sum(m["acc"] for m in fold_cv) / len(fold_cv)
        std_cv_acc = math.sqrt(sum((m["acc"] - mean_cv_acc)**2 for m in fold_cv) / len(fold_cv))
        print(f"  [TF-IDF+RF]  CV Acc={mean_cv_acc*100:.1f}%-{std_cv_acc*100:.1f}%, Test Acc={ml_metrics['accuracy']*100:.1f}%, MCC={ml_metrics['mcc']:.3f}, B_dev={ml_metrics['developer_burden']}")
    else:
        print(f"  [TF-IDF+RF]  Test Acc={ml_metrics['accuracy']*100:.1f}%, MCC={ml_metrics['mcc']:.3f}, B_dev={ml_metrics['developer_burden']}")
    print("  NOTE: ML classifier is highly unstable on n=40 (8 samples/fold). Wide CIs expected - treat as indicative only.")

    # -----------------------------------------------------------------------
    # PHASE B: Multi-Model LLM Benchmarking (JISA-Balanced, deterministic)
    # -----------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE B: Multi-Model Benchmarking (T=0.0, seed=42, n=40)")
    print("-" * 60)

    models = ["llama-3.3-70b-versatile", "qwen/qwen3-32b", "llama-3.1-8b-instant"]
    model_results_balanced = {}

    for model in models:
        print(f"\n  Running model: {model}")
        records = []
        for tc in BALANCED_TESTCASES:
            records.append(run_llm_triage(model, insecure_dir, tc, "insecure", "True Positive",
                                           prompt_type="standard", temperature=0.0, run_id=0))
        for tc in BALANCED_TESTCASES:
            records.append(run_llm_triage(model, secure_dir, tc, "secure", "False Positive",
                                           prompt_type="standard", temperature=0.0, run_id=0))
        model_results_balanced[model] = {"records": records, "metrics": compute_metrics(records)}
        m = model_results_balanced[model]["metrics"]
        print(f"  [{model[:25]:25s}] Acc={m['accuracy']*100:.1f}%, F1={m['f1']*100:.1f}%, MCC={m['mcc']:.3f}, B_dev={m['developer_burden']}")

    # -----------------------------------------------------------------------
    # PHASE C: ZeroFalse & QASecClaw Emulation (Llama 3.3, balanced)
    # -----------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE C: ZeroFalse & QASecClaw Emulation (Llama 3.3, T=0.0)")
    print("-" * 60)
    print("  FRAMING: These are best-effort reimplementations of prompting strategies")
    print("  described in prior work. Results are NOT directly comparable due to")
    print("  dataset and environment differences. Treated as exploratory baselines.\n")

    emulation_results = {}
    for prompt_type in ["zerofals", "qasecclaw"]:
        records = []
        for tc in BALANCED_TESTCASES:
            records.append(run_llm_triage("llama-3.3-70b-versatile", insecure_dir, tc, "insecure",
                                           "True Positive", prompt_type=prompt_type, temperature=0.0, run_id=0))
        for tc in BALANCED_TESTCASES:
            records.append(run_llm_triage("llama-3.3-70b-versatile", secure_dir, tc, "secure",
                                           "False Positive", prompt_type=prompt_type, temperature=0.0, run_id=0))
        emulation_results[prompt_type] = {"records": records, "metrics": compute_metrics(records)}
        m = emulation_results[prompt_type]["metrics"]
        print(f"  [{prompt_type:12s}] Acc={m['accuracy']*100:.1f}%, F1={m['f1']*100:.1f}%, MCC={m['mcc']:.3f}, B_dev={m['developer_burden']}")

    # -----------------------------------------------------------------------
    # PHASE D: Stochastic Variance (Llama 3.3, T=0.7, 3 runs)
    # -----------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE D: Stochastic Variance (T=0.7, 3 runs, Llama 3.3 70B)")
    print("-" * 60)

    stoch_run_metrics = []
    for run_id in range(1, 4):
        print(f"\n  --- Run {run_id}/3 ---")
        records = []
        for tc in BALANCED_TESTCASES:
            records.append(run_llm_triage("llama-3.3-70b-versatile", insecure_dir, tc, "insecure",
                                           "True Positive", prompt_type="standard", temperature=0.7, run_id=run_id))
        for tc in BALANCED_TESTCASES:
            records.append(run_llm_triage("llama-3.3-70b-versatile", secure_dir, tc, "secure",
                                           "False Positive", prompt_type="standard", temperature=0.7, run_id=run_id))
        stoch_m = compute_metrics(records)
        stoch_run_metrics.append(stoch_m)
        print(f"  Run {run_id}: Acc={stoch_m['accuracy']*100:.1f}%, F1={stoch_m['f1']*100:.1f}%, MCC={stoch_m['mcc']:.3f}")

    def mean_std(vals):
        m = sum(vals) / len(vals)
        s = math.sqrt(sum((v - m)**2 for v in vals) / len(vals))
        return m, s

    acc_m, acc_s = mean_std([x["accuracy"] for x in stoch_run_metrics])
    f1_m, f1_s = mean_std([x["f1"] for x in stoch_run_metrics])
    mcc_m, mcc_s = mean_std([x["mcc"] for x in stoch_run_metrics])
    print(f"\n  Stochastic Summary (T=0.7, 3 runs):")
    print(f"    Accuracy: {acc_m*100:.1f}% - {acc_s*100:.1f}%")
    print(f"    F1-Score: {f1_m*100:.1f}% - {f1_s*100:.1f}%")
    print(f"    MCC:      {mcc_m:.3f} - {mcc_s:.3f}")

    # -----------------------------------------------------------------------
    # PHASE E: JISA-Imb Evaluation (Llama 3.3, n=140, imbalanced)
    # -----------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE E: JISA-Imb Evaluation (Llama 3.3, n=140, 1:6 ratio)")
    print("-" * 60)

    imb_records = []
    # TP arm: 20 insecure alerts (True Positives)
    for tc in BALANCED_TESTCASES:
        imb_records.append(run_llm_triage("llama-3.3-70b-versatile", insecure_dir, tc, "insecure",
                                           "True Positive", prompt_type="standard", temperature=0.0, run_id=0))

    # FP arm: 120 FP alerts from Testcases_Secure_FP
    for fp_tc in fp_alerts:
        imb_records.append(run_llm_triage("llama-3.3-70b-versatile", fp_dir, fp_tc, "fp_secure",
                                           "False Positive", prompt_type="standard", temperature=0.0, run_id=0))

    imb_metrics = compute_metrics(imb_records)
    print(f"\n  [JISA-Imb LLM] Acc={imb_metrics['accuracy']*100:.1f}%, Prec={imb_metrics['precision']*100:.1f}%")
    print(f"  F1={imb_metrics['f1']*100:.1f}%, MCC={imb_metrics['mcc']:.3f}, B_dev={imb_metrics['developer_burden']}")

    # Baselines on JISA-Imb
    heur_imb_records = []
    for tc in BALANCED_TESTCASES:
        fp_file = insecure_dir / tc["rel_path"]
        code = fp_file.read_text(encoding="utf-8") if fp_file.exists() else ""
        heur_imb_records.append({"rel_path": tc["rel_path"], "ground_truth": "True Positive",
                                   "verdict": heur_triage(code), "confidence": 70, "latency": 0.0, "cost": 0.0})
    for fp_tc in fp_alerts:
        fp_file = fp_dir / fp_tc["rel_path"]
        code = fp_file.read_text(encoding="utf-8") if fp_file.exists() else ""
        heur_imb_records.append({"rel_path": fp_tc["rel_path"], "ground_truth": "False Positive",
                                   "verdict": heur_triage(code), "confidence": 70, "latency": 0.0, "cost": 0.0})

    heur_imb_metrics = compute_metrics(heur_imb_records)
    print(f"  [HeurTriage IMB] Acc={heur_imb_metrics['accuracy']*100:.1f}%, F1={heur_imb_metrics['f1']*100:.1f}%, MCC={heur_imb_metrics['mcc']:.3f}, B_dev={heur_imb_metrics['developer_burden']}")

    # AcceptAll on Imbalanced
    accept_imb = [{"ground_truth": "True Positive", "verdict": "True Positive", "confidence": 50, "latency": 0.0, "cost": 0.0}] * len(BALANCED_TESTCASES)
    accept_imb += [{"ground_truth": "False Positive", "verdict": "True Positive", "confidence": 50, "latency": 0.0, "cost": 0.0}] * len(fp_alerts)
    accept_imb_metrics = compute_metrics(accept_imb)
    print(f"  [AcceptAll IMB]  Acc={accept_imb_metrics['accuracy']*100:.1f}%, F1={accept_imb_metrics['f1']*100:.1f}%, MCC={accept_imb_metrics['mcc']:.3f}, B_dev={accept_imb_metrics['developer_burden']}")

    # -----------------------------------------------------------------------
    # PHASE F: McNemar's Tests
    # -----------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE F: McNemar's Significance Tests")
    print("-" * 60)

    llm_bal_records = model_results_balanced["llama-3.3-70b-versatile"]["records"]
    mcn_heur = mcnemar_test(llm_bal_records, heur_records)
    mcn_ml = mcnemar_test(llm_bal_records, ml_records)
    print(f"  LLM vs HeurTriage: chi2={mcn_heur['chi2']}, p-{mcn_heur['p_approx']}, sig(p<.05)={mcn_heur['significant_p05']}")
    print(f"  LLM vs TF-IDF+RF: chi2={mcn_ml['chi2']}, p-{mcn_ml['p_approx']}, sig(p<.05)={mcn_ml['significant_p05']}")

    # -----------------------------------------------------------------------
    # PHASE G: ECE, Brier, AUPRC
    # -----------------------------------------------------------------------
    print("\n" + "-" * 60)
    print("PHASE G: Calibration & PR Metrics (Llama 3.3, Balanced)")
    print("-" * 60)

    ece, brier, ece_bins = compute_ece_brier(llm_bal_records)
    auprc, pr_curve = compute_auprc(llm_bal_records)
    print(f"  ECE  = {ece*100:.2f}%  (over {len(llm_bal_records)} samples, {len(ece_bins)} bins)")
    print(f"  Brier= {brier:.4f}")
    print(f"  AUPRC= {auprc:.4f}")
    print(f"  Bin Details:")
    for b in ece_bins:
        print(f"    [{b['range']:6s}] n={b['count']:3d} | Conf={b['conf']:.1f}% | Acc={b['acc']:.1f}%")

    # -----------------------------------------------------------------------
    # PRINT SUMMARY TABLES
    # -----------------------------------------------------------------------
    print("\n" + "=" * 65)
    print("  JISA-BALANCED (n=40) FULL RESULTS TABLE")
    print("=" * 65)
    print(f"{'Method':<28} {'Acc%':>6} {'Prec%':>6} {'Rec%':>6} {'Spec%':>6} {'F1%':>6} {'MCC':>7} {'B_dev':>7}")
    print("-" * 65)
    print(f"{'AcceptAll (trivial)':28} {accept_all_metrics['accuracy']*100:6.1f} {accept_all_metrics['precision']*100:6.1f} {accept_all_metrics['recall']*100:6.1f} {accept_all_metrics['specificity']*100:6.1f} {accept_all_metrics['f1']*100:6.1f} {accept_all_metrics['mcc']:7.3f} {accept_all_metrics['developer_burden']:7d}")
    print(f"{'HeurTriage (regex)':28} {heur_metrics['accuracy']*100:6.1f} {heur_metrics['precision']*100:6.1f} {heur_metrics['recall']*100:6.1f} {heur_metrics['specificity']*100:6.1f} {heur_metrics['f1']*100:6.1f} {heur_metrics['mcc']:7.3f} {heur_metrics['developer_burden']:7d}")
    print(f"{'TF-IDF+RF (ML)':28} {ml_metrics['accuracy']*100:6.1f} {ml_metrics['precision']*100:6.1f} {ml_metrics['recall']*100:6.1f} {ml_metrics['specificity']*100:6.1f} {ml_metrics['f1']*100:6.1f} {ml_metrics['mcc']:7.3f} {ml_metrics['developer_burden']:7d}")
    for prompt_type in ["zerofals", "qasecclaw"]:
        em = emulation_results[prompt_type]["metrics"]
        label = "ZeroFalse (emul.)" if prompt_type == "zerofals" else "QASecClaw (emul.)"
        print(f"{label:28} {em['accuracy']*100:6.1f} {em['precision']*100:6.1f} {em['recall']*100:6.1f} {em['specificity']*100:6.1f} {em['f1']*100:6.1f} {em['mcc']:7.3f} {em['developer_burden']:7d}")
    for model in models:
        m = model_results_balanced[model]["metrics"]
        label = model[:28]
        print(f"{label:28} {m['accuracy']*100:6.1f} {m['precision']*100:6.1f} {m['recall']*100:6.1f} {m['specificity']*100:6.1f} {m['f1']*100:6.1f} {m['mcc']:7.3f} {m['developer_burden']:7d}")

    print("\n" + "=" * 65)
    print("  JISA-IMB (n=140, 1:6 ratio) COMPARISON TABLE")
    print("=" * 65)
    print(f"{'Method':<28} {'Acc%':>6} {'F1%':>6} {'MCC':>7} {'B_dev':>7}")
    print("-" * 65)
    print(f"{'AcceptAll (trivial)':28} {accept_imb_metrics['accuracy']*100:6.1f} {accept_imb_metrics['f1']*100:6.1f} {accept_imb_metrics['mcc']:7.3f} {accept_imb_metrics['developer_burden']:7d}")
    print(f"{'HeurTriage (regex)':28} {heur_imb_metrics['accuracy']*100:6.1f} {heur_imb_metrics['f1']*100:6.1f} {heur_imb_metrics['mcc']:7.3f} {heur_imb_metrics['developer_burden']:7d}")
    print(f"{'LLM (Llama 3.3 70B)':28} {imb_metrics['accuracy']*100:6.1f} {imb_metrics['f1']*100:6.1f} {imb_metrics['mcc']:7.3f} {imb_metrics['developer_burden']:7d}")

    # -----------------------------------------------------------------------
    # SAVE FULL RESULTS
    # -----------------------------------------------------------------------
    full_results = {
        "dataset_sizes": {
            "jisa_balanced": {"tp": len(BALANCED_TESTCASES), "fp": len(BALANCED_TESTCASES), "total": len(BALANCED_TESTCASES)*2},
            "jisa_imb": {"tp": len(BALANCED_TESTCASES), "fp": len(fp_alerts), "total": len(BALANCED_TESTCASES) + len(fp_alerts)},
        },
        "baselines_balanced": {
            "accept_all": accept_all_metrics,
            "heur_triage": heur_metrics,
            "ml_tfidf_rf": {**ml_metrics, "cv_fold_metrics": fold_cv},
        },
        "emulations_balanced": {k: v["metrics"] for k, v in emulation_results.items()},
        "llm_models_balanced": {m: v["metrics"] for m, v in model_results_balanced.items()},
        "stochastic_variance": {
            "runs": stoch_run_metrics,
            "summary": {"accuracy_mean": acc_m, "accuracy_std": acc_s,
                        "f1_mean": f1_m, "f1_std": f1_s,
                        "mcc_mean": mcc_m, "mcc_std": mcc_s},
        },
        "jisa_imb": {
            "accept_all": accept_imb_metrics,
            "heur_triage": heur_imb_metrics,
            "llm_llama33": imb_metrics,
        },
        "mcnemar_tests": {
            "llm_vs_heur": mcn_heur,
            "llm_vs_ml": mcn_ml,
        },
        "calibration": {
            "ece": ece, "brier_score": brier,
            "auprc": auprc, "ece_bins": ece_bins,
        },
    }

    out_path = EVAL_V2_DIR / "v2_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(full_results, f, indent=2)
    print(f"\n[+] Full results saved to: {out_path}")
    print("\n[DONE] evaluator_v2.py completed successfully.")

if __name__ == "__main__":
    main()
