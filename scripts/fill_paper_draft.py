"""
fill_paper_draft.py - Automatically fill [PENDING] placeholders in PAPER_DRAFT.md
from v2_results.json and audit_results.json output files.
"""

import json
import re
from pathlib import Path

PROJECT_DIR = Path(__file__).parent
V2_RESULTS = PROJECT_DIR / "results" / "evaluation_v2" / "v2_results.json"
AUDIT_RESULTS = PROJECT_DIR / "results" / "audit" / "audit_results.json"
PAPER_DRAFT = PROJECT_DIR / "PAPER_DRAFT.md"


def fmt(val, pct=False, decimals=1):
    if val is None:
        return "[N/A]"
    if pct:
        return f"{val * 100:.{decimals}f}"
    return f"{val:.{decimals}f}" if isinstance(val, float) else str(val)


def main():
    if not V2_RESULTS.exists():
        print(f"[!] v2_results.json not found at {V2_RESULTS}")
        return

    with open(V2_RESULTS, "r", encoding="utf-8") as f:
        v2 = json.load(f)

    audit = {}
    if AUDIT_RESULTS.exists():
        with open(AUDIT_RESULTS, "r", encoding="utf-8") as f:
            audit = json.load(f)

    content = PAPER_DRAFT.read_text(encoding="utf-8")
    original = content

    # ── Helpers ───────────────────────────────────────────────────────────────
    def pct(m, key):
        return fmt(m.get(key, 0), pct=True)

    def mcc_f(m):
        return f"{m.get('mcc', 0):.3f}"

    def bdev(m):
        return str(m.get("developer_burden", "N/A"))

    # ── Table 1: JISA-Balanced Full Results ───────────────────────────────────
    bsln = v2.get("baselines_balanced", {})
    heur = bsln.get("heur_triage", {})
    ml   = bsln.get("ml_tfidf_rf", {})
    emul = v2.get("emulations_balanced", {})
    zf   = emul.get("zerofals", {})
    qa   = emul.get("qasecclaw", {})
    llm_m = v2.get("llm_models_balanced", {})
    l8b  = llm_m.get("llama-3.1-8b-instant", {})
    q32  = llm_m.get("qwen/qwen3-32b", {})
    l70  = llm_m.get("llama-3.3-70b-versatile", {})
    calib = v2.get("calibration", {})
    mcn  = v2.get("mcnemar_tests", {})
    imb  = v2.get("jisa_imb", {})
    stoch = v2.get("stochastic_variance", {})

    # Abstract replacement
    content = content.replace(
        "achieves 92.5% accuracy and an MCC of 0.850 on the balanced study, and sustains strong performance under the imbalanced setting (MCC = 0.612)",
        f"achieves {pct(l70,'accuracy')}% accuracy and an MCC of {mcc_f(l70)} on the balanced study, and sustains strong performance under the imbalanced setting (MCC = {mcc_f(imb_llm)})"
    )
    content = content.replace(
        "achieves 92.5% accuracy and an MCC of 0.851 on the balanced study, and sustains strong performance under the imbalanced setting (MCC = 0.612)",
        f"achieves {pct(l70,'accuracy')}% accuracy and an MCC of {mcc_f(l70)} on the balanced study, and sustains strong performance under the imbalanced setting (MCC = {mcc_f(imb_llm)})"
    )

    # HeurTriage row
    content = re.sub(
        r"\|\s*HeurTriage\s*\(regex\)\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| HeurTriage (regex) | {pct(heur,'accuracy')} | {pct(heur,'precision')} | {pct(heur,'recall')} | {pct(heur,'specificity')} | {pct(heur,'f1')} | {mcc_f(heur)} | {bdev(heur)} |",
        content
    )

    # ML row
    content = re.sub(
        r"\|\s*TF-IDF\+RF\s*\(ML,\s*n=40\)\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| TF-IDF+RF (ML, n=40) | {pct(ml,'accuracy')} | {pct(ml,'precision')} | {pct(ml,'recall')} | {pct(ml,'specificity')} | {pct(ml,'f1')} | {mcc_f(ml)} | {bdev(ml)} |",
        content
    )

    # ZeroFalse row
    content = re.sub(
        r"\|\s*ZeroFalse\s*\(emul\.\)\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| ZeroFalse (emul.) | {pct(zf,'accuracy')} | {pct(zf,'precision')} | {pct(zf,'recall')} | {pct(zf,'specificity')} | {pct(zf,'f1')} | {mcc_f(zf)} | {bdev(zf)} |",
        content
    )

    # QASecClaw row
    content = re.sub(
        r"\|\s*QASecClaw\s*\(emul\.\)\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| QASecClaw (emul.) | {pct(qa,'accuracy')} | {pct(qa,'precision')} | {pct(qa,'recall')} | {pct(qa,'specificity')} | {pct(qa,'f1')} | {mcc_f(qa)} | {bdev(qa)} |",
        content
    )

    # Llama 3.1 8B row
    content = re.sub(
        r"\|\s*Llama\s*3\.1\s*8B\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| Llama 3.1 8B | {pct(l8b,'accuracy')} | {pct(l8b,'precision')} | {pct(l8b,'recall')} | {pct(l8b,'specificity')} | {pct(l8b,'f1')} | {mcc_f(l8b)} | {bdev(l8b)} |",
        content
    )

    # Qwen3 32B row
    content = re.sub(
        r"\|\s*Qwen3\s*32B\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| Qwen3 32B | {pct(q32,'accuracy')} | {pct(q32,'precision')} | {pct(q32,'recall')} | {pct(q32,'specificity')} | {pct(q32,'f1')} | {mcc_f(q32)} | {bdev(q32)} |",
        content
    )

    # Llama 3.3 70B row
    content = re.sub(
        r"\|\s*Llama\s*3\.3\s*70B\s*\(Primary\)\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| Llama 3.3 70B (Primary) | **{pct(l70,'accuracy')}** | **{pct(l70,'precision')}** | **{pct(l70,'recall')}** | **{pct(l70,'specificity')}** | **{pct(l70,'f1')}** | **{mcc_f(l70)}** | **{bdev(l70)}** |",
        content
    )

    # ── Table 2: JISA-Imb ─────────────────────────────────────────────────────
    imb_accept = imb.get("accept_all", {})
    imb_heur   = imb.get("heur_triage", {})
    imb_llm    = imb.get("llm_llama33", {})

    content = re.sub(
        r"\|\s*AcceptAll\s*\(trivial\)\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| AcceptAll (trivial) | {pct(imb_accept,'accuracy')} | {pct(imb_accept,'f1')} | {mcc_f(imb_accept)} | {bdev(imb_accept)} |",
        content
    )
    content = re.sub(
        r"\|\s*HeurTriage\s*\(regex\)\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| HeurTriage (regex) | {pct(imb_heur,'accuracy')} | {pct(imb_heur,'f1')} | {mcc_f(imb_heur)} | {bdev(imb_heur)} |",
        content
    )
    content = re.sub(
        r"\|\s*LLM\s*\(Llama\s*3\.3\s*70B\)\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| LLM (Llama 3.3 70B) | {pct(imb_llm,'accuracy')} | {pct(imb_llm,'f1')} | **{mcc_f(imb_llm)}** | {bdev(imb_llm)} |",
        content
    )

    # ── Table 3: Stochastic Variance ──────────────────────────────────────────
    runs = stoch.get("runs", [{}, {}, {}])
    summ = stoch.get("summary", {})
    for i, run in enumerate(runs[:3]):
        content = re.sub(
            r"\|\s*Run\s*" + str(i+1) + r"\s*\|[^|]*\|[^|]*\|[^|]*\|",
            f"| Run {i+1} | {pct(run,'accuracy')} | {pct(run,'f1')} | {mcc_f(run)} |",
            content
        )
    content = re.sub(
        r"\|\s*\*\*Mean\s*\+-\s*Std\*\*\s*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| **Mean +- Std** | {summ.get('accuracy_mean',0)*100:.1f}+-{summ.get('accuracy_std',0)*100:.1f} | {summ.get('f1_mean',0)*100:.1f}+-{summ.get('f1_std',0)*100:.1f} | {summ.get('mcc_mean',0):.3f}+-{summ.get('mcc_std',0):.3f} |",
        content
    )

    # ── Table 4: McNemar's ────────────────────────────────────────────────────
    mcn_heur = mcn.get("llm_vs_heur", {})
    mcn_ml   = mcn.get("llm_vs_ml", {})
    sig_heur = "Yes" if mcn_heur.get("significant_p05") else "No"
    sig_ml   = "Yes" if mcn_ml.get("significant_p05") else "No"

    content = re.sub(
        r"\|\s*LLM\s*vs\s*HeurTriage\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| LLM vs HeurTriage | {mcn_heur.get('b','?')} | {mcn_heur.get('c','?')} | {mcn_heur.get('chi2','?')} | {mcn_heur.get('p_approx','?')} | {sig_heur} |",
        content
    )
    content = re.sub(
        r"\|\s*LLM\s*vs\s*TF-IDF\+RF\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| LLM vs TF-IDF+RF | {mcn_ml.get('b','?')} | {mcn_ml.get('c','?')} | {mcn_ml.get('chi2','?')} | {mcn_ml.get('p_approx','?')} | {sig_ml} |",
        content
    )

    # ── Table 5: Calibration ──────────────────────────────────────────────────
    ece   = calib.get("ece", 0)
    brier = calib.get("brier_score", 0)
    auprc = calib.get("auprc", 0)
    bins  = calib.get("ece_bins", [{}, {}, {}])

    content = re.sub(
        r"\|\s*\[0-79\]%\s*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| [0-79]% | {bins[0].get('count', 0)} | {bins[0].get('conf', 0):.1f} | {bins[0].get('acc', 0):.1f} |",
        content
    )
    content = re.sub(
        r"\|\s*\[80-89\]%\s*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| [80-89]% | {bins[1].get('count', 0)} | {bins[1].get('conf', 0):.1f} | {bins[1].get('acc', 0):.1f} |",
        content
    )
    content = re.sub(
        r"\|\s*\[90-100\]%\s*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| [90-100]% | {bins[2].get('count', 0)} | {bins[2].get('conf', 0):.1f} | {bins[2].get('acc', 0):.1f} |",
        content
    )

    content = re.sub(
        r"\|\s*\*\*Overall\s*ECE\*\*\s*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| **Overall ECE** | | | **{ece*100:.2f}%** |",
        content
    )
    content = re.sub(
        r"\|\s*\*\*Brier\s*Score\*\*\s*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| **Brier Score** | | | **{brier:.4f}** |",
        content
    )
    content = re.sub(
        r"\|\s*\*\*AUPRC\*\*\s*\|[^|]*\|[^|]*\|[^|]*\|",
        f"| **AUPRC** | | | **{auprc:.4f}** |",
        content
    )

    # ── Table 6: Explanation Audit ────────────────────────────────────────────
    if audit:
        rubric = audit.get("rubric_audit", [])
        models_audit = ["llama-3.1-8b-instant", "qwen/qwen3-32b", "llama-3.3-70b-versatile"]
        labels_audit = ["Llama 3.1 8B", "Qwen3 32B", "Llama 3.3 70B"]
        for model, label in zip(models_audit, labels_audit):
            model_r = [r for r in rubric if r.get("model") == model]
            if model_r:
                mt  = sum(r["scores"]["total"] for r in model_r) / len(model_r)
                mtg = sum(r["scores"]["technical_grounding"] for r in model_r) / len(model_r)
                ma  = sum(r["scores"]["actionability"] for r in model_r) / len(model_r)
                mfc = sum(r["scores"]["flow_clarity"] for r in model_r) / len(model_r)
                content = re.sub(
                    r"\|\s*" + re.escape(label) + r"\s*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|",
                    f"| {label} | {mt:.2f} | {mtg:.2f} | {ma:.2f} | {mfc:.2f} |",
                    content
                )

    # ── Table 7: Contamination ────────────────────────────────────────────────
    if audit:
        contam = audit.get("contamination_probes", [])
        models_c = ["llama-3.1-8b-instant", "qwen/qwen3-32b", "llama-3.3-70b-versatile"]
        labels_c = ["Llama 3.1 8B", "Qwen3 32B", "Llama 3.3 70B"]
        for model, label in zip(models_c, labels_c):
            model_r = [r for r in contam if r.get("model") == model]
            if model_r:
                n_cont = sum(1 for r in model_r if r["grade"]["contamination_detected"])
                total  = len(model_r)
                rate   = n_cont / total * 100 if total > 0 else 0
                content = re.sub(
                    r"\|\s*" + re.escape(label) + r"\s*\|[^|]*\|[^|]*\|",
                    f"| {label} | {n_cont}/{total} | {rate:.1f}% |",
                    content
                )

    # ── Write output ──────────────────────────────────────────────────────────
    if content != original:
        PAPER_DRAFT.write_text(content, encoding="utf-8")
        remaining = content.count("[PENDING]")
        print(f"[+] PAPER_DRAFT.md updated. Remaining [PENDING] placeholders: {remaining}")
    else:
        print("[!] No replacements made — check placeholder format alignment.")

    # ── Print quick summary ───────────────────────────────────────────────────
    print("\n=== Quick Results Summary ===")
    print(f"JISA-Balanced (n=40):")
    print(f"  LLM Llama3.3:  Acc={pct(l70,'accuracy')}%, F1={pct(l70,'f1')}%, MCC={mcc_f(l70)}, B_dev={bdev(l70)}")
    print(f"  HeurTriage:    Acc={pct(heur,'accuracy')}%, F1={pct(heur,'f1')}%, MCC={mcc_f(heur)}, B_dev={bdev(heur)}")
    print(f"  TF-IDF+RF:     Acc={pct(ml,'accuracy')}%, F1={pct(ml,'f1')}%, MCC={mcc_f(ml)}, B_dev={bdev(ml)}")
    print(f"  ZeroFalse:     Acc={pct(zf,'accuracy')}%, F1={pct(zf,'f1')}%, MCC={mcc_f(zf)}")
    print(f"  QASecClaw:     Acc={pct(qa,'accuracy')}%, F1={pct(qa,'f1')}%, MCC={mcc_f(qa)}")
    print(f"\nJISA-Imb (n=140, 1:6):")
    print(f"  AcceptAll:     Acc={pct(imb_accept,'accuracy')}%, MCC={mcc_f(imb_accept)}, B_dev={bdev(imb_accept)}")
    print(f"  HeurTriage:    Acc={pct(imb_heur,'accuracy')}%, MCC={mcc_f(imb_heur)}, B_dev={bdev(imb_heur)}")
    print(f"  LLM Llama3.3:  Acc={pct(imb_llm,'accuracy')}%, MCC={mcc_f(imb_llm)}, B_dev={bdev(imb_llm)}")
    print(f"\nCalibration (LLM Balanced):")
    print(f"  ECE={ece*100:.2f}%, Brier={brier:.4f}, AUPRC={auprc:.4f}")
    print(f"\nMcNemar's Tests:")
    print(f"  LLM vs HeurTriage: chi2={mcn_heur.get('chi2')}, p={mcn_heur.get('p_approx')}, sig={sig_heur}")
    print(f"  LLM vs TF-IDF+RF:  chi2={mcn_ml.get('chi2')}, p={mcn_ml.get('p_approx')}, sig={sig_ml}")
    print(f"\nStochastic (T=0.7, 3 runs):")
    print(f"  Acc={summ.get('accuracy_mean',0)*100:.1f}+/-{summ.get('accuracy_std',0)*100:.1f}%")
    print(f"  F1={summ.get('f1_mean',0)*100:.1f}+/-{summ.get('f1_std',0)*100:.1f}%")
    print(f"  MCC={summ.get('mcc_mean',0):.3f}+/-{summ.get('mcc_std',0):.3f}")


if __name__ == "__main__":
    main()
