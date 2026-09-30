import os
import json
import time
import csv
import requests
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).parent.parent / ".env")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

PROJECT_DIR = Path(__file__).parent
EVAL_DIR = PROJECT_DIR / "results" / "evaluation"
EVAL_DIR.mkdir(parents=True, exist_ok=True)
CACHE_FILE = EVAL_DIR / "eval_cache.jsonl"

# The 20 selected testcases to evaluate (representing 20 True Positives and 20 False Positives)
TESTCASES = [
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
    {"rel_path": "CWE-601/codeql_1.py", "line": 12, "rule_id": "py/url-redirection", "msg": "Untrusted URL open redirect vulnerability."}
]

# API pricing standards per million tokens (Groq API)
PRICING = {
    "llama-3.3-70b-versatile": {"input": 0.59, "output": 0.79},
    "qwen/qwen3-32b": {"input": 0.20, "output": 0.20},
    "llama-3.1-8b-instant": {"input": 0.05, "output": 0.08}
}

# Cache system for persistent API results
_cache = {}
if CACHE_FILE.exists():
    with open(CACHE_FILE, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    record = json.loads(line)
                    cache_key = f"{record['model']}:{record['ablation_window']}:{record['ablation_marker']}:{record['test_type']}:{record['rel_path']}"
                    _cache[cache_key] = record
                except Exception:
                    pass

def save_to_cache(record):
    cache_key = f"{record['model']}:{record['ablation_window']}:{record['ablation_marker']}:{record['test_type']}:{record['rel_path']}"
    _cache[cache_key] = record
    with open(CACHE_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")

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

def make_prompt(rel_path, line, rule_id, alert_msg, code_snippet):
    return f"""You are an elite, highly experienced software security reviewer.
Your objective is to triage a static analysis alert generated by CodeQL on a Python codebase.

[CONTEXT]
File Path: {rel_path}
Line Number: {line}
CodeQL Rule ID: {rule_id}
CodeQL Alert Message: {alert_msg}

[CODE SNIPPET]
The snippet shows the flagged code with line numbers.
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

def extract_json(text):
    if not text:
        return {}
    text_str = str(text).strip()
    if "```json" in text_str:
        try:
            parts = text_str.split("```json")
            if len(parts) > 1:
                content = parts[1].split("```")[0].strip()
                return json.loads(content)
        except Exception:
            pass
    elif "```" in text_str:
        try:
            parts = text_str.split("```")
            if len(parts) > 1:
                content = parts[1].strip()
                if content.startswith("python") or content.startswith("json"):
                    content = "\n".join(content.split("\n")[1:])
                return json.loads(content)
        except Exception:
            pass
    start = text_str.find('{')
    end = text_str.rfind('}')
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text_str[start:end+1])
        except Exception:
            pass
    try:
        return json.loads(text_str)
    except Exception:
        return {}

def query_groq(model, prompt):
    if model == "llama-3.3-70b-versatile" and GROQ_API_KEY:
        url = GROQ_URL
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "llama-3.3-70b-versatile",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
            "response_format": {"type": "json_object"}
        }
        provider_name = "Groq"
    elif model == "llama-3.1-8b-instant" and GROQ_API_KEY:
        url = GROQ_URL
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": "llama-3.1-8b-instant",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
            "response_format": {"type": "json_object"}
        }
        provider_name = "Groq"
    elif model == "llama-3.3-70b-versatile" and OPENROUTER_API_KEY:
        url = OPENROUTER_URL
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost",
            "X-Title": "CodeQL LLM Hybrid"
        }
        payload = {
            "model": "meta-llama/llama-3.3-70b-instruct",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0
        }
        provider_name = "OpenRouter"
    elif model == "llama-3.1-8b-instant" and OPENROUTER_API_KEY:
        url = OPENROUTER_URL
        headers = {
            "Authorization": f"Bearer {OPENROUTER_API_KEY}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost",
            "X-Title": "CodeQL LLM Hybrid"
        }
        payload = {
            "model": "meta-llama/llama-3.1-8b-instruct",
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0
        }
        provider_name = "OpenRouter"
    else:
        url = GROQ_URL
        headers = {
            "Authorization": f"Bearer {GROQ_API_KEY}",
            "Content-Type": "application/json"
        }
        payload = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
            "response_format": {"type": "json_object"}
        }
        provider_name = "Groq"
    
    for attempt in range(5):
        try:
            start_t = time.time()
            r = requests.post(url, headers=headers, json=payload, timeout=30)
            latency = time.time() - start_t
            if r.status_code == 200:
                resp_json = r.json()
                choice_content = resp_json["choices"][0]["message"]["content"]
                triage_result = extract_json(choice_content)
                usage = resp_json.get("usage", {})
                prompt_tokens = usage.get("prompt_tokens", 0)
                completion_tokens = usage.get("completion_tokens", 0)
                return triage_result, prompt_tokens, completion_tokens, latency
            elif r.status_code == 429:
                if provider_name == "Groq" and OPENROUTER_API_KEY:
                    print(f"    [Groq 429] Falling back to OpenRouter instantly...")
                    provider_name = "OpenRouter"
                    url = OPENROUTER_URL
                    headers = {
                        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
                        "Content-Type": "application/json",
                        "HTTP-Referer": "http://localhost",
                        "X-Title": "CodeQL LLM Hybrid"
                    }
                    model_mapping = {
                        "llama-3.3-70b-versatile": "meta-llama/llama-3.3-70b-instruct",
                        "llama-3.1-8b-instant": "meta-llama/llama-3.1-8b-instruct",
                        "qwen/qwen3-32b": "qwen/qwen3-32b"
                    }
                    payload = {
                        "model": model_mapping.get(model, model),
                        "messages": [{"role": "user", "content": prompt}],
                        "temperature": 0.0
                    }
                    continue
                else:
                    wait = min(120, 15 * (2**attempt))
                    print(f"    [{provider_name} 429 Rate Limit] Waiting {wait}s...")
                    time.sleep(wait)
            else:
                print(f"    [{provider_name} HTTP {r.status_code}] {r.text[:100]} | Retrying...")
                time.sleep(5)
        except Exception as e:
            print(f"    [{provider_name} API Exception] {e} | Retrying...")
            time.sleep(5)
            
    return {"verdict": "Unclear", "confidence": 0, "severity": "Info", "reason": "API Failure", "recommendation": ""}, 0, 0, 0.0

def run_triage(model, test_type, testcase, window_size=7, highlight_marker=True):
    cache_key = f"{model}:{window_size}:{highlight_marker}:{test_type}:{testcase['rel_path']}"
    if cache_key in _cache:
        return _cache[cache_key]
        
    print(f"  [*] Executing triage: Model={model} | Type={test_type} | File={testcase['rel_path']}")
    
    if test_type == "insecure":
        base_dir = PROJECT_DIR / "repos" / "SecurityEval" / "Testcases_Insecure_Code"
        ground_truth = "True Positive"
    else:
        base_dir = PROJECT_DIR / "repos" / "SecurityEval" / "Testcases_Secure_Patched"
        ground_truth = "False Positive"
        
    snippet = extract_snippet(base_dir, testcase["rel_path"], testcase["line"], window_size, highlight_marker, testcase["msg"])
    prompt = make_prompt(testcase["rel_path"], testcase["line"], testcase["rule_id"], testcase["msg"], snippet)
    
    triage, prompt_tokens, completion_tokens, latency = query_groq(model, prompt)
    
    # Calculate estimated cost
    price_info = PRICING.get(model, {"input": 0.0, "output": 0.0})
    cost = (prompt_tokens / 1_000_000 * price_info["input"]) + (completion_tokens / 1_000_000 * price_info["output"])
    
    record = {
        "model": model,
        "test_type": test_type,
        "rel_path": testcase["rel_path"],
        "line": testcase["line"],
        "rule_id": testcase["rule_id"],
        "ground_truth": ground_truth,
        "verdict": triage.get("verdict", "Unclear"),
        "confidence": triage.get("confidence", 0),
        "severity": triage.get("severity", "Info"),
        "reason": triage.get("reason", ""),
        "recommendation": triage.get("recommendation", ""),
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "latency": latency,
        "cost": cost,
        "ablation_window": window_size,
        "ablation_marker": highlight_marker
    }
    
    save_to_cache(record)
    time.sleep(1.0) # Cushion for rate limit
    return record

def compute_metrics(records):
    # Calculate Confusion Matrix
    tp, fp, tn, fn, unclear = 0, 0, 0, 0, 0
    total_latency = 0.0
    total_cost = 0.0
    total_prompt_tokens = 0
    total_completion_tokens = 0
    
    for r in records:
        verdict = r["verdict"]
        gt = r["ground_truth"]
        total_latency += r["latency"]
        total_cost += r["cost"]
        total_prompt_tokens += r["prompt_tokens"]
        total_completion_tokens += r["completion_tokens"]
        
        if verdict == "Unclear":
            unclear += 1
            if gt == "True Positive":
                fn += 1 # Unclear on insecure counts as false negative (failed to raise alarm)
            else:
                fp += 1 # Unclear on secure counts as false positive (failed to filter out)
        elif verdict == "True Positive":
            if gt == "True Positive":
                tp += 1
            else:
                fp += 1
        elif verdict == "False Positive":
            if gt == "False Positive":
                tn += 1
            else:
                fn += 1
                
    accuracy = (tp + tn) / len(records) if len(records) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn, "unclear": unclear,
        "accuracy": accuracy, "precision": precision, "recall": recall,
        "specificity": specificity, "f1": f1,
        "mean_latency": total_latency / len(records) if len(records) > 0 else 0,
        "total_cost": total_cost,
        "mean_prompt_tokens": total_prompt_tokens / len(records) if len(records) > 0 else 0,
        "mean_completion_tokens": total_completion_tokens / len(records) if len(records) > 0 else 0
    }

def compute_ece(records, num_bins=3):
    # Groups confidence values into bins: [0, 80), [80, 90), [90, 100]
    bins = [
        {"lower": 0, "upper": 80, "items": []},
        {"lower": 80, "upper": 90, "items": []},
        {"lower": 90, "upper": 101, "items": []}
    ]
    
    for r in records:
        conf = r["confidence"]
        # Determine if classification was correct
        correct = 0
        if r["verdict"] == r["ground_truth"]:
            correct = 1
        
        # Place in appropriate bin
        for b in bins:
            if b["lower"] <= conf < b["upper"]:
                b["items"].append({"conf": conf / 100.0, "correct": correct})
                break
                
    ece = 0.0
    total_n = len(records)
    
    bin_stats = []
    for b in bins:
        items = b["items"]
        if not items:
            bin_stats.append({"range": f"{b['lower']}-{b['upper']-1}", "count": 0, "acc": 0.0, "conf": 0.0})
            continue
        acc = sum(x["correct"] for x in items) / len(items)
        conf = sum(x["conf"] for x in items) / len(items)
        weight = len(items) / total_n
        ece += weight * abs(acc - conf)
        bin_stats.append({
            "range": f"{b['lower']}-{b['upper']-1}",
            "count": len(items),
            "acc": acc * 100.0,
            "conf": conf * 100.0
        })
        
    return ece, bin_stats

def main():
    if not GROQ_API_KEY:
        print("[!] GROQ_API_KEY environment variable is not defined.")
        return
        
    print("\n========================================================")
    
    # 1. Evaluate Multi-Model Benchmarks
    print("\n--- PHASE 1: Running Multi-Model Benchmarking ---")
    models = ["llama-3.3-70b-versatile", "qwen/qwen3-32b", "llama-3.1-8b-instant"]
    model_results = {}
    
    for m in models:
        records = []
        # Insecure alerts (True Positives)
        for tc in TESTCASES:
            records.append(run_triage(m, "insecure", tc, window_size=7, highlight_marker=True))
        # Secure alerts (False Positives)
        for tc in TESTCASES:
            records.append(run_triage(m, "secure", tc, window_size=7, highlight_marker=True))
            
        model_results[m] = {
            "records": records,
            "metrics": compute_metrics(records)
        }
    
    # 2. Evaluate Window Ablations on Llama 3.3 70B
    print("\n--- PHASE 2: Running Window Size Ablations (Model: llama-3.3-70b-versatile) ---")
    windows = [2, 14] # 2 (5 lines total), 14 (29 lines total). Default 7 (15 lines total) is already done.
    window_results = {}
    
    # Copy default W=7 results
    window_results[7] = model_results["llama-3.3-70b-versatile"]["metrics"]
    
    for w in windows:
        records = []
        for tc in TESTCASES:
            records.append(run_triage("llama-3.3-70b-versatile", "insecure", tc, window_size=w, highlight_marker=True))
        for tc in TESTCASES:
            records.append(run_triage("llama-3.3-70b-versatile", "secure", tc, window_size=w, highlight_marker=True))
        window_results[w] = compute_metrics(records)
        
    # 3. Evaluate Marker Ablations on Llama 3.3 70B
    print("\n--- PHASE 3: Running Sink Marker Ablation (Model: llama-3.3-70b-versatile) ---")
    marker_records = []
    for tc in TESTCASES:
        marker_records.append(run_triage("llama-3.3-70b-versatile", "insecure", tc, window_size=7, highlight_marker=False))
    for tc in TESTCASES:
        marker_records.append(run_triage("llama-3.3-70b-versatile", "secure", tc, window_size=7, highlight_marker=False))
    no_marker_metrics = compute_metrics(marker_records)
    
    # 4. Expected Calibration Error (ECE) calculation on Llama 3.3 70B (Default Setup)
    default_records = model_results["llama-3.3-70b-versatile"]["records"]
    ece, ece_bins = compute_ece(default_records)
    
    print("\n========================================================")
    print("EVALUATION EXECUTION RESULTS SUMMARY")
    print("========================================================")
    
    print("\n1. Model Comparison Table:")
    print(f"| Model | Accuracy (%) | Precision (%) | Recall/Sens. (%) | Specificity (%) | F1-Score (%) | Mean Latency (s) | Total Cost ($) |")
    print(f"|---|---|---|---|---|---|---|---|")
    for m in models:
        met = model_results[m]["metrics"]
        print(f"| {m} | {met['accuracy']*100:.1f}% | {met['precision']*100:.1f}% | {met['recall']*100:.1f}% | {met['specificity']*100:.1f}% | {met['f1']*100:.1f}% | {met['mean_latency']:.2f}s | ${met['total_cost']:.4f} |")
        
    print("\n2. Baseline Comparison:")
    print("  - Trivial Baseline (Accept All Alerts): Accuracy=50.0%, Precision=50.0%, Recall=100.0%, Specificity=0.0%, F1=66.7%")
    
    print("\n3. Window Size Ablation Study:")
    print(f"| Window Size | Total Lines | Accuracy (%) | Precision (%) | Recall (%) | Specificity (%) | F1-Score (%) | Mean Latency (s) |")
    print(f"|---|---|---|---|---|---|---|---|")
    for w in [2, 7, 14]:
        met = window_results[w]
        print(f"| W={w} | {w*2+1} lines | {met['accuracy']*100:.1f}% | {met['precision']*100:.1f}% | {met['recall']*100:.1f}% | {met['specificity']*100:.1f}% | {met['f1']*100:.1f}% | {met['mean_latency']:.2f}s |")
        
    print("\n4. Highlight Marker Ablation Study:")
    print(f"| Setup | Accuracy (%) | Precision (%) | Recall (%) | Specificity (%) | F1-Score (%) |")
    print(f"|---|---|---|---|---|---|")
    met_w_marker = model_results["llama-3.3-70b-versatile"]["metrics"]
    print(f"| With Marker (>>>) | {met_w_marker['accuracy']*100:.1f}% | {met_w_marker['precision']*100:.1f}% | {met_w_marker['recall']*100:.1f}% | {met_w_marker['specificity']*100:.1f}% | {met_w_marker['f1']*100:.1f}% |")
    print(f"| Without Marker (Ablation) | {no_marker_metrics['accuracy']*100:.1f}% | {no_marker_metrics['precision']*100:.1f}% | {no_marker_metrics['recall']*100:.1f}% | {no_marker_metrics['specificity']*100:.1f}% | {no_marker_metrics['f1']*100:.1f}% |")

    print(f"\n5. Expected Calibration Error (ECE) for Llama 3.3 70B: {ece*100:.2f}%")
    print(f"Bin Details:")
    for b in ece_bins:
        print(f"  - Bin [{b['range']}]: Count={b['count']}, Mean Self-Reported Conf.={b['conf']:.1f}%, Actual Accuracy={b['acc']:.1f}%")
        
    # Save evaluation summary JSON
    summary_data = {
        "models": {m: model_results[m]["metrics"] for m in models},
        "ablations": {
            "windows": {str(w): window_results[w] for w in [2, 7, 14]},
            "marker": {
                "with_marker": met_w_marker,
                "without_marker": no_marker_metrics
            }
        },
        "ece": {
            "ece_score": ece,
            "bins": ece_bins
        }
    }
    with open(EVAL_DIR / "evaluation_results.json", "w", encoding="utf-8") as outf:
        json.dump(summary_data, outf, indent=2)
    print(f"\n[+] Wrote full evaluation data JSON to: {EVAL_DIR / 'evaluation_results.json'}")

if __name__ == "__main__":
    main()
