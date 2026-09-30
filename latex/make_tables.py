#!/usr/bin/env python3
"""Generate LaTeX table bodies and inline macros for the CodeQL+LLM triage paper.

    python3 make_tables.py <results_dir> <out_dir>

Sources
-------
evaluation_v2/v2_results.json   balanced and imbalanced benchmarks, baselines,
                                SOTA emulations, LLM models, stochastic variance,
                                McNemar tests, calibration
evaluation/evaluation_results.json  per-model results and the context-window
                                and marker ablations
audit/audit_results.json        explanation rubric audit and contamination probe
pilot/alerts.csv                the raw CodeQL alert inventory

Nothing here is typed by hand.
"""
import csv
import json
import statistics
import sys
from collections import Counter
from pathlib import Path

RES = Path(sys.argv[1] if len(sys.argv) > 1 else "../results")
OUT = Path(sys.argv[2] if len(sys.argv) > 2 else "tables")
OUT.mkdir(parents=True, exist_ok=True)


def load(rel):
    with open(RES / rel, encoding="utf-8") as f:
        return json.load(f)


def write(name, body):
    (OUT / name).write_text(body.rstrip() + "\n", encoding="utf-8")
    print(f"wrote {OUT / name}")


def f3(x):
    return "--" if x is None else f"{x:.3f}"


def tex(s):
    return s.replace("_", r"\_").replace("%", r"\%").replace("&", r"\&")


V2 = load("evaluation_v2/v2_results.json")
EV = load("evaluation/evaluation_results.json")
AU = load("audit/audit_results.json")

NAMES = {
    "accept_all": "Accept-all (no triage)",
    "heur_triage": "Heuristic regex triage",
    "ml_tfidf_rf": "TF-IDF + Random Forest",
    "zerofals": "ZeroFalse-style emulation",
    "qasecclaw": "QASec-CLAW-style emulation",
    "llama-3.3-70b-versatile": r"LLM: \texttt{llama-3.3-70b}",
    "qwen/qwen3-32b": r"LLM: \texttt{qwen3-32b}",
    "llama-3.1-8b-instant": r"LLM: \texttt{llama-3.1-8b}",
    "llm_llama33": r"LLM: \texttt{llama-3.3-70b}",
}
BEST = {"ml_tfidf_rf", "qwen/qwen3-32b", "llm_llama33"}


def row(key, m, bold=False):
    b = (lambda t: r"\textbf{" + t + "}") if bold else (lambda t: t)
    return " & ".join([
        b(NAMES.get(key, tex(key))),
        f"{m['tp']}/{m['fp']}/{m['tn']}/{m['fn']}",
        str(m.get("unclear", 0)),
        b(f3(m["accuracy"])), f3(m["precision"]), f3(m["recall"]),
        f3(m["specificity"]), b(f3(m["f1"])), b(f3(m.get("mcc"))),
        b(str(m["developer_burden"])),
    ]) + r" \\"


# ------------------------------------------------- Table: balanced benchmark
rows = []
for group in ("baselines_balanced", "emulations_balanced", "llm_models_balanced"):
    if rows:
        rows.append(r"\addlinespace")
    for k, m in V2[group].items():
        rows.append(row(k, m, bold=(k in BEST)))
write("tab_balanced.tex", "\n".join(rows))

# ------------------------------------------------- Table: imbalanced benchmark
rows = [row(k, m, bold=(k in BEST)) for k, m in V2["jisa_imb"].items()]
write("tab_imbalanced.tex", "\n".join(rows))

# ------------------------------------------------- Table: McNemar
LBL = {"llm_vs_heur": "LLM vs.\\ heuristic",
       "llm_vs_ml": "LLM vs.\\ TF-IDF+RF"}
rows = []
for k, m in V2["mcnemar_tests"].items():
    verdict = "sig." if m["significant_p05"] else r"\textbf{n.s.}"
    rows.append(" & ".join([
        LBL.get(k, tex(k)), str(m["b"]), str(m["c"]),
        f"{m['chi2']:.3f}", f"{m['p_approx']:.4f}", verdict,
    ]) + r" \\")
write("tab_mcnemar.tex", "\n".join(rows))

# ------------------------------------------------- Table: stochastic variance
sv = V2["stochastic_variance"]
rows = []
for i, m in enumerate(sv["runs"], 1):
    rows.append(" & ".join([
        f"Run {i}", f"{m['tp']}/{m['fp']}/{m['tn']}/{m['fn']}", str(m["unclear"]),
        f3(m["accuracy"]), f3(m["f1"]), f3(m["mcc"]), str(m["developer_burden"]),
    ]) + r" \\")
s = sv["summary"]
rows.append(r"\addlinespace")
rows.append(" & ".join([
    r"\textbf{Mean}", "--", "--",
    r"\textbf{" + f"{s['accuracy_mean']:.3f}" + "}",
    r"\textbf{" + f"{s['f1_mean']:.3f}" + "}",
    r"\textbf{" + f"{s['mcc_mean']:.3f}" + "}",
    "--",
]) + r" \\")
rows.append(" & ".join([
    "SD", "--", "--",
    f"{s['accuracy_std']:.3f}", f"{s['f1_std']:.3f}", f"{s['mcc_std']:.3f}", "--",
]) + r" \\")
write("tab_variance.tex", "\n".join(rows))

# ------------------------------------------------- Table: ablations
rows = []
for w, m in sorted(EV["ablations"]["windows"].items(), key=lambda kv: int(kv[0])):
    bold = w == "7"
    b = (lambda t: r"\textbf{" + t + "}") if bold else (lambda t: t)
    rows.append(" & ".join([
        b(f"$W = {w}$ lines"), f"{m['tp']}/{m['fp']}/{m['tn']}/{m['fn']}",
        str(m["unclear"]), b(f3(m["accuracy"])),
        f3(m["specificity"]), b(f3(m["f1"])), f"{m['mean_latency']:.2f}",
    ]) + r" \\")
rows.append(r"\addlinespace")
for key, lab in (("with_marker", "Alert marker present"),
                 ("without_marker", "Alert marker removed")):
    m = EV["ablations"]["marker"][key]
    rows.append(" & ".join([
        lab, f"{m['tp']}/{m['fp']}/{m['tn']}/{m['fn']}", str(m["unclear"]),
        f3(m["accuracy"]), f3(m["specificity"]),
        f3(m["f1"]), f"{m['mean_latency']:.2f}",
    ]) + r" \\")
write("tab_ablation.tex", "\n".join(rows))

# ------------------------------------------------- Table: cost / latency
rows = []
for k, m in V2["llm_models_balanced"].items():
    e = EV["models"].get(k, {})
    rows.append(" & ".join([
        NAMES.get(k, tex(k)),
        f"{m['mean_latency']:.2f}",
        f"{m['total_cost']:.4f}",
        f"{e.get('mean_prompt_tokens', float('nan')):.0f}",
        f"{e.get('mean_completion_tokens', float('nan')):.0f}",
        str(m["developer_burden"]),
    ]) + r" \\")
write("tab_cost.tex", "\n".join(rows))

# ------------------------------------------------- Table: rubric audit
DIMS = [("technical_grounding", "Technical grounding"),
        ("actionability", "Actionability"),
        ("flow_clarity", "Data-flow clarity"),
        ("total", "Total (max 6)")]
models = ["llama-3.3-70b-versatile", "qwen/qwen3-32b", "llama-3.1-8b-instant"]
ra = AU["rubric_audit"]
rows = []
for key, lab in DIMS:
    cells = [lab if key != "total" else r"\textbf{" + lab + "}"]
    for m in models:
        sub = [r for r in ra if r["model"] == m]
        v = statistics.mean(r["scores"][key] for r in sub)
        cells.append((r"\textbf{" + f"{v:.2f}" + "}") if key == "total" else f"{v:.2f}")
    rows.append(" & ".join(cells) + r" \\")
write("tab_rubric.tex", "\n".join(rows))

# ------------------------------------------------- Table: contamination probe
cp = AU["contamination_probes"]
rows = []
for m in models:
    sub = [c for c in cp if c["model"] == m]
    det = sum(1 for c in sub if c["grade"]["contamination_detected"])
    hits = statistics.mean(c["grade"]["hit_count"] for c in sub)
    thr = sub[0]["grade"]["threshold"]
    rows.append(" & ".join([
        NAMES.get(m, tex(m)), str(len(sub)), f"{hits:.2f}", str(thr),
        r"\textbf{" + str(det) + "}",
    ]) + r" \\")
write("tab_contamination.tex", "\n".join(rows))

# ------------------------------------------------- Table: alert inventory
with open(RES / "pilot" / "alerts.csv", newline="", encoding="utf-8") as f:
    alerts = list(csv.DictReader(f))
cnt = Counter(a["rule_id"] for a in alerts)
rows = []
for rule, n in cnt.most_common(10):
    rows.append(f"\\texttt{{{tex(rule)}}} & {n} \\\\")
write("tab_alerts.tex", "\n".join(rows))

# ------------------------------------------------- inline macros
cal = V2["calibration"]
bal = V2["dataset_sizes"]["jisa_balanced"]
imb = V2["dataset_sizes"]["jisa_imb"]
llm_b = V2["llm_models_balanced"]["llama-3.3-70b-versatile"]
ml_b = V2["baselines_balanced"]["ml_tfidf_rf"]
heur_b = V2["baselines_balanced"]["heur_triage"]
llm_i = V2["jisa_imb"]["llm_llama33"]
heur_i = V2["jisa_imb"]["heur_triage"]
all_i = V2["jisa_imb"]["accept_all"]
mn_ml = V2["mcnemar_tests"]["llm_vs_ml"]
mn_he = V2["mcnemar_tests"]["llm_vs_heur"]

macros = [
    (r"\Nbal", str(bal["total"])), (r"\NbalTP", str(bal["tp"])), (r"\NbalFP", str(bal["fp"])),
    (r"\Nimb", str(imb["total"])), (r"\NimbTP", str(imb["tp"])), (r"\NimbFP", str(imb["fp"])),
    (r"\Nalerts", str(len(alerts))), (r"\Nrules", str(len(cnt))),
    (r"\LLMbalAcc", f3(llm_b["accuracy"])), (r"\LLMbalF", f3(llm_b["f1"])),
    (r"\LLMbalMcc", f3(llm_b["mcc"])), (r"\LLMbalBurden", str(llm_b["developer_burden"])),
    (r"\MLbalAcc", f3(ml_b["accuracy"])), (r"\MLbalF", f3(ml_b["f1"])),
    (r"\MLbalMcc", f3(ml_b["mcc"])), (r"\MLbalBurden", str(ml_b["developer_burden"])),
    (r"\HeurbalAcc", f3(heur_b["accuracy"])), (r"\HeurbalMcc", f3(heur_b["mcc"])),
    (r"\LLMimbPrec", f3(llm_i["precision"])), (r"\LLMimbMcc", f3(llm_i["mcc"])),
    (r"\LLMimbAcc", f3(llm_i["accuracy"])), (r"\LLMimbBurden", str(llm_i["developer_burden"])),
    (r"\LLMimbUnclear", str(llm_i["unclear"])),
    (r"\HeurimbPrec", f3(heur_i["precision"])), (r"\HeurimbMcc", f3(heur_i["mcc"])),
    (r"\HeurimbBurden", str(heur_i["developer_burden"])),
    (r"\AllimbPrec", f3(all_i["precision"])), (r"\AllimbBurden", str(all_i["developer_burden"])),
    (r"\McnMlP", f"{mn_ml['p_approx']:.4f}"), (r"\McnMlB", str(mn_ml["b"])),
    (r"\McnMlC", str(mn_ml["c"])), (r"\McnMlChi", f"{mn_ml['chi2']:.3f}"),
    (r"\McnHeP", f"{mn_he['p_approx']:.4f}"), (r"\McnHeB", str(mn_he["b"])),
    (r"\McnHeC", str(mn_he["c"])), (r"\McnHeChi", f"{mn_he['chi2']:.3f}"),
    (r"\Ece", f"{cal['ece']:.3f}"), (r"\Brier", f"{cal['brier_score']:.3f}"),
    (r"\Auprc", f"{cal['auprc']:.3f}"),
    (r"\AccMean", f3(V2["stochastic_variance"]["summary"]["accuracy_mean"])),
    (r"\FMeanSd", f"{V2['stochastic_variance']['summary']['f1_mean']:.3f} \\pm "
                 f"{V2['stochastic_variance']['summary']['f1_std']:.3f}"),
    (r"\MccMeanSd", f"{V2['stochastic_variance']['summary']['mcc_mean']:.3f} \\pm "
                    f"{V2['stochastic_variance']['summary']['mcc_std']:.3f}"),
    (r"\Nrubric", str(len(ra))), (r"\Nprobe", str(len(cp))),
    (r"\NrubricCWE", str(len({r["rule_id"] for r in ra}))),
    (r"\ProbeThr", str(cp[0]["grade"]["threshold"])),
    (r"\BestWindow", "7"),
    (r"\WtwoAcc", f3(EV["ablations"]["windows"]["2"]["accuracy"])),
    (r"\WsevenAcc", f3(EV["ablations"]["windows"]["7"]["accuracy"])),
    (r"\WfourteenAcc", f3(EV["ablations"]["windows"]["14"]["accuracy"])),
]
write("macros.tex", "\n".join(rf"\newcommand{{{n}}}{{{v}}}" for n, v in macros))
print("\nAll tables generated from:", RES.resolve())


# ===========================================================================
# v2: doc tu tap danh gia DUNG LAI tu false positive THAT (real_eval)
# ===========================================================================
import json as _json2

def sci(x, d=2):
    """So rat nho -> dang mu, khong lam tron ve 0."""
    import math as _mm
    if x <= 0:
        return r"\ensuremath{0}"
    e = _mm.floor(_mm.log10(x)); m_ = x / 10 ** e
    return f"\\ensuremath{{{m_:.{d}f}\\times 10^{{{e}}}}}"


_REAL = RES / "real_eval" / "real_eval_results.json"
if _REAL.exists():
    _d = _json2.loads(_REAL.read_text(encoding="utf-8"))
    _c = _d["config"]

    _LAB = {"accept_all": "Accept all", "heuristic": "Regex heuristic",
            "tfidf_rf": r"TF-IDF + RF", "tfidf_msgonly": r"TF-IDF, message only",
            "llm": "LLM"}

    def _rows(setname):
        out = []
        for r in _d.get(setname, []):
            out.append(" & ".join([
                _LAB.get(r["triager"], r["triager"]),
                str(r["n"]),
                f"{r['tp']}/{r['fp']}/{r['tn']}/{r['fn']}",
                f"{r['accuracy']:.4f}",
                f"{r['mcc']:.4f}",
                f"[{r['mcc_ci_lo']:.3f}, {r['mcc_ci_hi']:.3f}]",
                str(r["burden_fp_plus_50fn"]),
            ]) + r" \\")
        return "\n".join(out)

    write("tab_real_balanced.tex", _rows("balanced"))
    write("tab_real_imbalanced.tex", _rows("imbalanced"))

    _pairs = []
    for k, v in _d.get("mcnemar", {}).items():
        setname, pair = k.split(":", 1)
        a, b = pair.split("_vs_")
        _pairs.append(" & ".join([
            setname.capitalize(), _LAB.get(a, a), _LAB.get(b, b),
            str(v["b"]), str(v["c"]), sci(v["p"]) if v["p"] < 1e-3 else f"{v['p']:.3f}",
        ]) + r" \\")
    write("tab_real_mcnemar.tex", "\n".join(_pairs))

    def _get(setname, tri, field):
        for r in _d.get(setname, []):
            if r["triager"] == tri:
                return r[field]
        return None

    _m = [
        (r"\RNtp", str(_c["n_tp"])), (r"\RNfp", str(_c["n_fp"])),
        (r"\RNbal", str(_c["n_balanced"])), (r"\RNimb", str(_c["n_imbalanced"])),
        (r"\RImbRatio", f"{_c['imb_ratio']:.2f}"),
        (r"\RNrulesFp", str(_c["n_rules_fp"])), (r"\RNmsgFp", str(_c["n_messages_fp"])),
        (r"\RNrulesTp", str(_c["n_rules_tp"])),
        (r"\RNrulesShared", str(_c["n_rules_shared"])),
        (r"\RBoot", f"{_c['boot']:,}".replace(",", "{,}")),
    ]
    for setname, tag in (("balanced", "Bal"), ("imbalanced", "Imb")):
        for tri, short in (("accept_all", "All"), ("heuristic", "Heur"),
                           ("tfidf_rf", "Tfidf"), ("tfidf_msgonly", "Msg")):
            for field, fs in (("mcc", "Mcc"), ("accuracy", "Acc")):
                v = _get(setname, tri, field)
                if v is not None:
                    _m.append((rf"\R{short}{tag}{fs}", f"{v:.4f}"))
            for field, fs in (("mcc_ci_lo", "Lo"), ("mcc_ci_hi", "Hi")):
                v = _get(setname, tri, field)
                if v is not None:
                    _m.append((rf"\R{short}{tag}{fs}", f"{v:.3f}"))
            v = _get(setname, tri, "burden_fp_plus_50fn")
            if v is not None:
                _m.append((rf"\R{short}{tag}Bur", str(v)))

    _mc = _d.get("mcnemar", {})
    for key, name in (("balanced:tfidf_rf_vs_tfidf_msgonly", "RMsgSame"),
                      ("imbalanced:tfidf_rf_vs_tfidf_msgonly", "RMsgSameImb"),
                      ("balanced:heuristic_vs_tfidf_rf", "RHeurVsTfidf"),
                      ("imbalanced:heuristic_vs_tfidf_rf", "RHeurVsTfidfImb")):
        if key in _mc:
            p = _mc[key]["p"]
            _m.append((rf"\{name}", sci(p) if p < 1e-3 else f"{p:.3f}"))

    with open(OUT / "macros.tex", "a", encoding="utf-8") as _f:
        _f.write("\n%% --- v2: tap danh gia dung lai tu FP that ---\n")
        for n, v in _m:
            _f.write(rf"\newcommand{{{n}}}{{{v}}}" + "\n")
    print(f"wrote {len(_m)} macro v2 tu real_eval_results.json")


# ===========================================================================
# Phan them: phan tich thanh phan kho alert va co che cua baseline heuristic.
#
# Moi so duoi day la mot ham thuan cua hai file goc:
#   results/pilot/alerts.csv              59 true positive
#   results/real_fp/real_fp_alerts.json  127 false positive
# Khong co buoc lay mau ngau nhien nao, nen ket qua tai lap duoc tuyet doi.
# ===========================================================================
import collections as _coll
import math as _math

_TPCSV = RES / "pilot" / "alerts.csv"
_FPJSON = RES / "real_fp" / "real_fp_alerts.json"

if _TPCSV.exists() and _FPJSON.exists():
    with open(_TPCSV, newline="", encoding="utf-8") as _f:
        _tp = [{"rel_path": r["file_path"], "line": int(r["start_line"]),
                "rule_id": r["rule_id"], "msg": r["message"]}
               for r in csv.DictReader(_f)]
    _fp = json.loads(_FPJSON.read_text(encoding="utf-8"))

    def _clause(a):
        """Tra ve (dieu khoan nao cua heuristic ban ra quyet dinh, quyet dinh do).

        Sao lai dung logic heuristic() trong fix2_rebuild_and_triage.py.
        """
        low = (a.get("rel_path") or "").lower()
        m = (a.get("msg") or "").lower()
        r = (a.get("rule_id") or "").lower()
        for k in ("test", "example", "mock", "sample"):
            if k in low:
                return "path-keyword", "accept" if False else "reject"
        if any(k in r for k in ("hardcoded", "clear-text", "weak")):
            return "rule-keyword", "accept"
        if "may" in m or "could" in m:
            return "hedge-word", "reject"
        return "default", "accept"

    _ctp = _coll.Counter(a["rule_id"] for a in _tp)
    _cfp = _coll.Counter(a["rule_id"] for a in _fp)
    _shared = sorted(set(_ctp) & set(_cfp))
    _tp_on_shared = sum(_ctp[r] for r in _shared)
    _fp_on_shared = sum(_cfp[r] for r in _shared)

    _msg_tp = len({a["msg"] for a in _tp})
    _msg_fp = len({a["msg"] for a in _fp})

    _acc_tp = sum(1 for a in _tp if _clause(a)[1] == "accept")
    _acc_fp = sum(1 for a in _fp if _clause(a)[1] == "accept")
    _TP, _FP = _acc_tp, _acc_fp
    _FN, _TN = len(_tp) - _acc_tp, len(_fp) - _acc_fp
    _den = _math.sqrt((_TP + _FP) * (_TP + _FN) * (_TN + _FP) * (_TN + _FN))
    _mcc_full = ((_TP * _TN - _FP * _FN) / _den) if _den else 0.0

    # --- bang 1: rule xuat hien o ca hai lop
    _rows_shared = []
    for r in sorted(_shared, key=lambda r: (-_cfp[r], -_ctp[r], r)):
        _rows_shared.append(
            r"\texttt{%s} & %d & %d & %.2f \\" %
            (r.replace("_", r"\_"), _ctp[r], _cfp[r], _cfp[r] / _ctp[r]))
    (OUT / "tab_rule_overlap.tex").write_text("\n".join(_rows_shared) + "\n",
                                              encoding="utf-8")

    # --- bang 2: mau thong diep cua lop false positive
    _rows_tmpl = []
    for m, n in _coll.Counter(a["msg"] for a in _fp).most_common():
        _short = m if len(m) <= 78 else m[:75] + "..."
        _short = (_short.replace("\\", "").replace("&", r"\&")
                        .replace("%", r"\%").replace("_", r"\_")
                        .replace("#", r"\#").replace("$", r"\$"))
        _rows_tmpl.append(r"%d & %s \\" % (n, _short))
    (OUT / "tab_fp_templates.tex").write_text("\n".join(_rows_tmpl) + "\n",
                                              encoding="utf-8")

    # --- bang 3: dieu khoan nao cua heuristic quyet dinh
    _rows_cl = []
    _order = ["path-keyword", "rule-keyword", "hedge-word", "default"]
    _verd = {"path-keyword": "reject", "rule-keyword": "accept",
             "hedge-word": "reject", "default": "accept"}
    _cl_tp = _coll.Counter(_clause(a)[0] for a in _tp)
    _cl_fp = _coll.Counter(_clause(a)[0] for a in _fp)
    for c in _order:
        _rows_cl.append(
            r"\texttt{%s} & %s & %d & %d \\" %
            (c, _verd[c], _cl_tp.get(c, 0), _cl_fp.get(c, 0)))
    (OUT / "tab_heur_clauses.tex").write_text("\n".join(_rows_cl) + "\n",
                                              encoding="utf-8")

    # --- bang 4: ma tran McNemar day du
    _mcn = _d.get("mcnemar", {}) if "_d" in dir() else {}
    _LBL = {"accept_all": "Accept-all", "heuristic": "Heuristic",
            "tfidf_rf": "TF-IDF+RF", "tfidf_msgonly": "TF-IDF msg"}
    _rows_mcn = []
    for _set, _tag in (("balanced", "Balanced"), ("imbalanced", "Imbalanced")):
        for _k, _v in _mcn.items():
            if not _k.startswith(_set + ":"):
                continue
            _a, _b = _k.split(":", 1)[1].split("_vs_")
            _p = _v["p"]
            _ps = sci(_p) if _p < 1e-3 else "%.4f" % _p
            _rows_mcn.append(
                r"%s & %s & %s & %d & %d & %s \\" %
                (_tag, _LBL.get(_a, _a), _LBL.get(_b, _b),
                 _v.get("b", 0), _v.get("c", 0), _ps))
    if _rows_mcn:
        (OUT / "tab_mcnemar_full.tex").write_text("\n".join(_rows_mcn) + "\n",
                                                  encoding="utf-8")

    _m2 = [
        (r"\CNtpRules", str(len(_ctp))),
        (r"\CNfpRules", str(len(_cfp))),
        (r"\CNshared", str(len(_shared))),
        (r"\CTpOnShared", str(_tp_on_shared)),
        (r"\CFpOnShared", str(_fp_on_shared)),
        (r"\CTpOnSharedPct", "%.1f" % (100 * _tp_on_shared / len(_tp))),
        (r"\CFpOnSharedPct", "%.1f" % (100 * _fp_on_shared / len(_fp))),
        (r"\CMsgTp", str(_msg_tp)),
        (r"\CMsgFp", str(_msg_fp)),
        (r"\CMultTp", "%.2f" % (len(_tp) / _msg_tp)),
        (r"\CMultFp", "%.2f" % (len(_fp) / _msg_fp)),
        (r"\CAlertsPerRuleTp", "%.2f" % (len(_tp) / len(_ctp))),
        (r"\CAlertsPerRuleFp", "%.2f" % (len(_fp) / len(_cfp))),
        (r"\CHeurFullTP", str(_TP)), (r"\CHeurFullFP", str(_FP)),
        (r"\CHeurFullTN", str(_TN)), (r"\CHeurFullFN", str(_FN)),
        (r"\CHeurFullMcc", "%.4f" % _mcc_full),
        (r"\CHeurAccTpPct", "%.1f" % (100 * _acc_tp / len(_tp))),
        (r"\CHeurAccFpPct", "%.1f" % (100 * _acc_fp / len(_fp))),
        (r"\CNall", str(len(_tp) + len(_fp))),
        (r"\CAllPrec", "%.4f" % (len(_tp) / (len(_tp) + len(_fp)))),
        (r"\CPathClauseTp", str(_cl_tp.get("path-keyword", 0))),
        (r"\CPathClauseFp", str(_cl_fp.get("path-keyword", 0))),
        (r"\CHedgeTp", str(_cl_tp.get("hedge-word", 0))),
        (r"\CHedgeFp", str(_cl_fp.get("hedge-word", 0))),
        (r"\CFpSecure", str(sum(1 for a in _fp if a.get("source") == "secure_fp"))),
        (r"\CFpPatched", str(sum(1 for a in _fp if a.get("source") == "secure_patched"))),
    ]
    with open(OUT / "macros.tex", "a", encoding="utf-8") as _f:
        _f.write("\n%% --- thanh phan kho alert va co che heuristic ---\n")
        for n, v in _m2:
            _f.write(rf"\newcommand{{{n}}}{{{v}}}" + "\n")
    print(f"wrote {len(_m2)} macro thanh phan kho + 4 bang")


# ===========================================================================
# Phan them 2: phan bo theo nhom CWE.
# Moi thu muc trong corpus mang ten mot nhom CWE, nen duong dan tuong doi cho
# biet nhom ma khong can nhan them. Day la mot loi tat thu ba ma benchmark chua.
# ===========================================================================
if _TPCSV.exists() and _FPJSON.exists():
    def _cwe(path):
        return (path or "").split("/")[0]

    _cwe_tp = _coll.Counter(_cwe(a["rel_path"]) for a in _tp)
    _cwe_fp = _coll.Counter(_cwe(a["rel_path"]) for a in _fp)
    _fp_groups = sorted(_cwe_fp, key=lambda c: (-_cwe_fp[c], -_cwe_tp.get(c, 0), c))
    _only_tp = sorted(set(_cwe_tp) - set(_cwe_fp))
    _tp_on_only = sum(_cwe_tp[c] for c in _only_tp)

    _rows_cwe = []
    for c in _fp_groups:
        _rows_cwe.append(r"\texttt{%s} & %d & %d \\" %
                         (c, _cwe_tp.get(c, 0), _cwe_fp[c]))
    _rows_cwe.append(r"\midrule")
    _rows_cwe.append(r"%d further groups & %d & 0 \\" % (len(_only_tp), _tp_on_only))
    (OUT / "tab_cwe.tex").write_text("\n".join(_rows_cwe) + "\n", encoding="utf-8")

    _m3 = [
        (r"\DCweTp", str(len(_cwe_tp))),
        (r"\DCweFp", str(len(_cwe_fp))),
        (r"\DCweBoth", str(len(set(_cwe_tp) & set(_cwe_fp)))),
        (r"\DCweAll", str(len(set(_cwe_tp) | set(_cwe_fp)))),
        (r"\DCweOnlyTp", str(len(_only_tp))),
        (r"\DTpOnOnly", str(_tp_on_only)),
        (r"\DTpOnOnlyPct", "%.1f" % (100 * _tp_on_only / len(_tp))),
    ]
    with open(OUT / "macros.tex", "a", encoding="utf-8") as _f:
        _f.write("\n%% --- phan bo theo nhom CWE ---\n")
        for n, v in _m3:
            _f.write(rf"\newcommand{{{n}}}{{{v}}}" + "\n")
    print(f"wrote {len(_m3)} macro CWE + 1 bang")
