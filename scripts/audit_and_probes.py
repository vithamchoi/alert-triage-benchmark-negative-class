"""
audit_and_probes.py - Step 4: Human-in-the-Loop Explanation Audit & Contamination Probes
Addresses JISA peer review Gaps 8 & 9.

Gap 8: Systematic explanation quality auditing using a Structured Rubric.
Gap 9: Description-based contamination probe (refined test for training data memorization).
"""

import os
import json
import time
import re
from pathlib import Path
from dotenv import load_dotenv
import requests

# ─── Environment Setup ────────────────────────────────────────────────────────
load_dotenv(Path(__file__).parent.parent / ".env")
GROQ_API_KEY = os.getenv("GROQ_API_KEY")
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY")
GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"

PROJECT_DIR = Path(__file__).parent
AUDIT_DIR = PROJECT_DIR / "results" / "audit"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)

# ─── Models Under Test ────────────────────────────────────────────────────────
MODELS = [
    "llama-3.3-70b-versatile",
    "qwen/qwen3-32b",
    "llama-3.1-8b-instant",
]

# ─── Sample cases for audit (5 per model: 15 total) ──────────────────────────
AUDIT_CASES = [
    {"rel_path": "CWE-022/codeql_1.py", "line": 13, "rule_id": "py/path-injection",
     "msg": "This path depends on a user-provided value.", "type": "insecure", "expected_gt": "True Positive"},
    {"rel_path": "CWE-080/author_1.py", "line": 12, "rule_id": "py/reflective-xss",
     "msg": "Reflected Cross-Site Scripting (XSS) vulnerability.", "type": "insecure", "expected_gt": "True Positive"},
    {"rel_path": "CWE-295/codeql_1.py", "line": 4, "rule_id": "py/request-without-cert-validation",
     "msg": "SSL certificate validation is disabled.", "type": "insecure", "expected_gt": "True Positive"},
    {"rel_path": "CWE-078/codeql_1.py", "line": 13, "rule_id": "py/command-line-injection",
     "msg": "This command line depends on a user-provided value.", "type": "insecure", "expected_gt": "True Positive"},
    {"rel_path": "CWE-327/codeql_3.py", "line": 8, "rule_id": "py/weak-sensitive-data-hashing",
     "msg": "Using insecure MD5 hashing for sensitive data.", "type": "insecure", "expected_gt": "True Positive"},
]

# ─── Structured Explanatory Rubric ───────────────────────────────────────────
RUBRIC = {
    "Technical Grounding (0-2)": {
        "2": "Explanation accurately identifies the specific data-flow path, taint source, and vulnerable sink with CWE-level reasoning.",
        "1": "Explanation partially describes the vulnerability mechanism but misses sink/source specificity.",
        "0": "Explanation is generic, incorrect, or does not reference actual code logic.",
    },
    "Actionability (0-2)": {
        "2": "Recommendation is specific, immediately applicable (e.g. use X.escape(), parameterized queries), and correct for the CWE.",
        "1": "Recommendation is appropriate but vague (e.g. 'sanitize input', 'validate properly').",
        "0": "No recommendation, irrelevant, or recommends an insecure practice.",
    },
    "Flow Clarity (0-2)": {
        "2": "Explanation traces the complete path from source to sink using concrete references (e.g. line numbers, variable names).",
        "1": "Explanation mentions relevant code elements but doesn't fully trace flow.",
        "0": "Explanation is unclear, contradictory, or fails to reference code.",
    }
}

# ─── Contamination Probe Cases ───────────────────────────────────────────────
CONTAMINATION_CASES = [
    {
        "file_ref": "SecurityEval/Testcases_Insecure_Code/CWE-020/codeql_3.py",
        "probe_question": (
            "Given only the filename 'SecurityEval/Testcases_Insecure_Code/CWE-020/codeql_3.py', "
            "describe in detail what this specific file does: what are its endpoint routes, "
            "what exact variable names does it define, what URL pattern does it use, "
            "and what is the precise vulnerability it demonstrates?"
        ),
        "grading_signals": ["incomplete-hostname", "regexp", "example.com", "redirect", "target"],
        "contamination_threshold": 3
    },
    {
        "file_ref": "SecurityEval/Testcases_Insecure_Code/CWE-094/codeql_1.py",
        "probe_question": (
            "Given only the filename 'SecurityEval/Testcases_Insecure_Code/CWE-094/codeql_1.py', "
            "describe what this file does: its exact function names, what user input it accepts, "
            "and what specific dangerous operation it performs (be as specific as possible about the code structure)."
        ),
        "grading_signals": ["exec", "eval", "code-injection", "expression", "user input"],
        "contamination_threshold": 3
    },
    {
        "file_ref": "SecurityEval/Testcases_Insecure_Code/CWE-502/sonar_1.py",
        "probe_question": (
            "Given only the filename 'SecurityEval/Testcases_Insecure_Code/CWE-502/sonar_1.py', "
            "describe precisely what function this file implements, what YAML function it calls, "
            "and what its Flask route path is (if any)."
        ),
        "grading_signals": ["yaml.load", "unsafe", "deserialization", "flask", "safe_load"],
        "contamination_threshold": 3
    },
    {
        "file_ref": "SecurityEval/Testcases_Insecure_Code/CWE-605/author_1.py",
        "probe_question": (
            "Given only the filename 'SecurityEval/Testcases_Insecure_Code/CWE-605/author_1.py', "
            "describe the exact function this file implements, what socket configuration it uses, "
            "and what specific binding address it calls (provide exact parameters if you know them)."
        ),
        "grading_signals": ["0.0.0.0", "bind", "echoServer", "all interfaces", "socket"],
        "contamination_threshold": 3
    },
    {
        "file_ref": "SecurityEval/Testcases_Insecure_Code/CWE-090/codeql_1.py",
        "probe_question": (
            "Given only the filename 'SecurityEval/Testcases_Insecure_Code/CWE-090/codeql_1.py', "
            "describe what this file's Flask route does, what LDAP library it imports, "
            "and exactly how the user input flows into the LDAP query."
        ),
        "grading_signals": ["ldap", "search_filter", "uid", "username", "ldap3"],
        "contamination_threshold": 3
    },
]

# ─── API Caller ───────────────────────────────────────────────────────────────
def call_llm(model, prompt, temperature=0.0):
    if OPENROUTER_API_KEY:
        url = OPENROUTER_URL
        or_map = {
            "llama-3.3-70b-versatile": "meta-llama/llama-3.3-70b-instruct",
            "qwen/qwen3-32b": "qwen/qwen3-32b",
            "llama-3.1-8b-instant": "meta-llama/llama-3.1-8b-instruct",
        }
        headers = {"Authorization": f"Bearer {OPENROUTER_API_KEY}", "Content-Type": "application/json",
                   "HTTP-Referer": "http://localhost", "X-Title": "JISA Audit"}
        payload = {"model": or_map.get(model, model),
                   "messages": [{"role": "user", "content": prompt}],
                   "temperature": temperature}
    elif GROQ_API_KEY:
        url = GROQ_URL
        headers = {"Authorization": f"Bearer {GROQ_API_KEY}", "Content-Type": "application/json"}
        groq_map = {
            "llama-3.3-70b-versatile": "llama-3.3-70b-versatile",
            "qwen/qwen3-32b": "qwen/qwen3-32b",
            "llama-3.1-8b-instant": "llama-3.1-8b-instant",
        }
        payload = {"model": groq_map.get(model, model),
                   "messages": [{"role": "user", "content": prompt}],
                   "temperature": temperature}
    else:
        return "No API key configured", 0.0

    for attempt in range(4):
        try:
            t0 = time.time()
            r = requests.post(url, headers=headers, json=payload, timeout=60)
            latency = time.time() - t0
            if r.status_code == 200:
                return r.json()["choices"][0]["message"]["content"], latency
            elif r.status_code == 429:
                wait = min(120, 15 * (2**attempt))
                print(f"    [429 Rate Limit] Waiting {wait}s...")
                time.sleep(wait)
            else:
                print(f"    [HTTP {r.status_code}] Retrying...")
                time.sleep(5)
        except Exception as e:
            print(f"    [Exception] {e}")
            time.sleep(5)
    return "API failure after retries", 0.0

# ─── Rubric Scoring ──────────────────────────────────────────────────────────
def score_explanation_with_rubric(explanation_text, rule_id, file_path, alert_msg):
    """
    Score the LLM explanation according to 3-dimension rubric.
    Returns dimension scores, total (0-6), and grader rationale.
    """
    rubric_prompt = f"""You are a senior code security expert tasked with grading the quality of an automated LLM triage explanation.

[ALERT CONTEXT]
File: {file_path}
Rule: {rule_id}
Alert: {alert_msg}

[LLM EXPLANATION TO GRADE]
{explanation_text}

[RUBRIC]
Score each dimension 0, 1, or 2 based on the following criteria:

DIMENSION 1 - Technical Grounding (0-2):
  2 = Accurately identifies the specific data-flow path, taint source, and vulnerable sink with CWE-level reasoning.
  1 = Partially describes the vulnerability mechanism but misses sink/source specificity.
  0 = Generic, incorrect, or does not reference actual code logic.

DIMENSION 2 - Actionability (0-2):
  2 = Recommendation is specific, immediately applicable, and correct for this CWE (e.g., use html.escape(), parameterized queries).
  1 = Recommendation is appropriate but vague (e.g., 'sanitize input').
  0 = No recommendation, irrelevant, or recommends an insecure practice.

DIMENSION 3 - Flow Clarity (0-2):
  2 = Traces the complete path from source to sink using concrete references (line numbers, variable names).
  1 = Mentions relevant code elements but doesn't fully trace flow.
  0 = Unclear, contradictory, or fails to reference the code.

[OUTPUT FORMAT]
Respond with a JSON object:
{{
  "technical_grounding": <0, 1, or 2>,
  "actionability": <0, 1, or 2>,
  "flow_clarity": <0, 1, or 2>,
  "total": <sum 0-6>,
  "rationale": "<brief grader rationale for each dimension>"
}}"""

    response, _ = call_llm("llama-3.3-70b-versatile", rubric_prompt, temperature=0.0)

    # Parse JSON from response
    s = str(response).find("{")
    e = str(response).rfind("}")
    if s != -1 and e != -1:
        try:
            return json.loads(response[s:e+1])
        except Exception:
            pass
    return {"technical_grounding": 0, "actionability": 0, "flow_clarity": 0, "total": 0, "rationale": "Parse error"}

# ─── Contamination Probe Grading ─────────────────────────────────────────────
def grade_contamination(response_text, probe_case):
    """
    Grade contamination by counting specific implementation signals in the response.
    If model accurately describes specific variable names/endpoints/code patterns
    without having seen the source, it indicates likely training data memorization.
    """
    response_lower = response_text.lower()
    signals_hit = [sig for sig in probe_case["grading_signals"] if sig.lower() in response_lower]
    hit_count = len(signals_hit)
    is_contaminated = hit_count >= probe_case["contamination_threshold"]
    return {
        "signals_hit": signals_hit,
        "hit_count": hit_count,
        "threshold": probe_case["contamination_threshold"],
        "contamination_detected": is_contaminated,
        "contamination_level": "HIGH" if hit_count >= probe_case["contamination_threshold"] else
                               ("MEDIUM" if hit_count > 0 else "NONE"),
    }

# ─── Main ─────────────────────────────────────────────────────────────────────
def main():
    print("\n" + "=" * 65)
    print("  AUDIT & CONTAMINATION PROBES - JISA Gap 8 & 9")
    print("=" * 65)

    if not GROQ_API_KEY and not OPENROUTER_API_KEY:
        print("[!] No API key found. Set GROQ_API_KEY or OPENROUTER_API_KEY in .env")
        return

    insecure_dir = PROJECT_DIR / "repos" / "SecurityEval" / "Testcases_Insecure_Code"

    # ═══════════════════════════════════════════════════════════════════════
    # GAP 8: Explanation Quality Audit (15 samples, 5 per model)
    # ═══════════════════════════════════════════════════════════════════════
    print("\n--- GAP 8: Explanation Quality Rubric Audit ---")
    print("  Rubric: Technical Grounding (0-2) + Actionability (0-2) + Flow Clarity (0-2) = max 6")
    print("  NOTE: Double-blind grading performed by LLM rubric evaluator (surrogate for human judge)\n")

    audit_results = []

    for model in MODELS:
        print(f"\n  Model: {model}")
        model_scores = []
        for case in AUDIT_CASES:
            # Get code snippet
            fp = insecure_dir / case["rel_path"]
            if not fp.exists():
                print(f"    [!] File not found: {fp}")
                continue

            with open(fp, "r", encoding="utf-8") as f:
                lines = f.readlines()
            start = max(0, case["line"] - 8)
            end = min(len(lines), case["line"] + 8)
            snippet_lines = []
            for idx in range(start, end):
                ln = idx + 1
                content = lines[idx].rstrip("\r\n")
                if ln == case["line"]:
                    snippet_lines.append(f"{ln:4d} >>> {content}  # <--- CODEQL: {case['msg']}")
                else:
                    snippet_lines.append(f"{ln:4d}     {content}")
            snippet = "\n".join(snippet_lines)

            # Generate triage explanation
            triage_prompt = f"""You are a security code reviewer triaging a CodeQL alert.

[CONTEXT]
File: {case['rel_path']}
Line: {case['line']}
Rule: {case['rule_id']}
Alert: {case['msg']}

[CODE SNIPPET]
```python
{snippet}
```

[TASK]
Classify the alert (True Positive or False Positive), explain the data-flow reason in technical detail,
and provide a specific remediation recommendation.

[OUTPUT FORMAT]
{{
  "verdict": "True Positive" | "False Positive" | "Unclear",
  "confidence": <0-100>,
  "severity": "High" | "Medium" | "Low" | "Info",
  "reason": "<detailed technical explanation>",
  "recommendation": "<specific remediation>"
}}"""

            response, latency = call_llm(model, triage_prompt, temperature=0.0)
            print(f"    Triaging {case['rel_path']} ...", end=" ")

            # Extract reason and recommendation from response
            reason = ""
            recommendation = ""
            s = str(response).find("{")
            e = str(response).rfind("}")
            if s != -1 and e != -1:
                try:
                    parsed = json.loads(response[s:e+1])
                    reason = parsed.get("reason", "")
                    recommendation = parsed.get("recommendation", "")
                except Exception:
                    reason = response[:300]

            full_explanation = f"REASON: {reason}\nRECOMMENDATION: {recommendation}"

            # Grade with rubric
            scores = score_explanation_with_rubric(full_explanation, case["rule_id"], case["rel_path"], case["msg"])
            model_scores.append(scores)
            print(f"Score={scores['total']}/6 (TG={scores['technical_grounding']}, Act={scores['actionability']}, FC={scores['flow_clarity']})")

            audit_results.append({
                "model": model,
                "rel_path": case["rel_path"],
                "rule_id": case["rule_id"],
                "explanation": full_explanation[:500],
                "scores": scores,
            })
            time.sleep(1.5)

        if model_scores:
            mean_total = sum(s["total"] for s in model_scores) / len(model_scores)
            mean_tg = sum(s["technical_grounding"] for s in model_scores) / len(model_scores)
            mean_act = sum(s["actionability"] for s in model_scores) / len(model_scores)
            mean_fc = sum(s["flow_clarity"] for s in model_scores) / len(model_scores)
            print(f"\n  [{model[:28]:28s}] Mean: Total={mean_total:.2f}/6 | TG={mean_tg:.2f} | Act={mean_act:.2f} | FC={mean_fc:.2f}")

    # Print audit summary table
    print("\n" + "=" * 65)
    print("  EXPLANATION AUDIT SUMMARY TABLE")
    print("=" * 65)
    print(f"{'Model':<32} {'Mean Total':>10} {'Mean TG':>8} {'Mean Act':>9} {'Mean FC':>8}")
    print("-" * 65)
    for model in MODELS:
        model_r = [r for r in audit_results if r["model"] == model]
        if model_r:
            mt = sum(r["scores"]["total"] for r in model_r) / len(model_r)
            mtg = sum(r["scores"]["technical_grounding"] for r in model_r) / len(model_r)
            mact = sum(r["scores"]["actionability"] for r in model_r) / len(model_r)
            mfc = sum(r["scores"]["flow_clarity"] for r in model_r) / len(model_r)
            print(f"{model:<32} {mt:10.2f} {mtg:8.2f} {mact:9.2f} {mfc:8.2f}")

    # ═══════════════════════════════════════════════════════════════════════
    # GAP 9: Description-Based Contamination Probes (5 cases, 3 models)
    # ═══════════════════════════════════════════════════════════════════════
    print("\n\n--- GAP 9: Refined Description-Based Contamination Probes ---")
    print("  METHODOLOGY: Models are asked to describe specific SecurityEval files")
    print("  using ONLY the filename. If the model accurately describes implementation")
    print("  details (variable names, endpoints, parameters), this indicates likely")
    print("  training data memorization. This is NOT a verbatim completion test.\n")

    contamination_results = []

    for model in MODELS:
        print(f"\n  Model: {model}")
        for case in CONTAMINATION_CASES:
            print(f"    Probing: {case['file_ref']} ...", end=" ")
            response, latency = call_llm(model, case["probe_question"], temperature=0.0)
            grade = grade_contamination(response, case)

            print(f"Signals={grade['hit_count']}/{len(case['grading_signals'])} | Level={grade['contamination_level']}")

            contamination_results.append({
                "model": model,
                "file_ref": case["file_ref"],
                "response_excerpt": str(response)[:400],
                "grade": grade,
            })
            time.sleep(1.2)

    # Contamination summary
    print("\n" + "=" * 65)
    print("  CONTAMINATION PROBE SUMMARY")
    print("=" * 65)
    print(f"{'Model':<32} {'Contaminated':>13} {'Rate':>6}")
    print("-" * 65)
    for model in MODELS:
        model_r = [r for r in contamination_results if r["model"] == model]
        n_cont = sum(1 for r in model_r if r["grade"]["contamination_detected"])
        total = len(model_r)
        rate = n_cont / total * 100 if total > 0 else 0
        print(f"{model:<32} {n_cont:>5}/{total:<7} {rate:>5.1f}%")

    print("\n  INTERPRETATION:")
    print("  HIGH contamination level suggests the model has seen SecurityEval in training.")
    print("  This is a THREAT TO VALIDITY for our evaluation — results may overestimate")
    print("  LLM triage capability due to memorized benchmark familiarity.")
    print("  We acknowledge this limitation in the Threats to Validity section.")

    # Save full audit results
    full_audit = {
        "rubric_audit": audit_results,
        "contamination_probes": contamination_results,
    }
    out_path = AUDIT_DIR / "audit_results.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(full_audit, f, indent=2, ensure_ascii=False)
    print(f"\n[+] Audit results saved to: {out_path}")
    print("\n[DONE] audit_and_probes.py completed successfully.")

if __name__ == "__main__":
    main()
