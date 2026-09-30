"""Bai 09, buoc 2: dung lai hai tap danh gia tu du lieu THAT, roi chay ca ba
bo phan loai - KE CA TF-IDF tren tap mat can bang, la nhanh bi thieu.

Doc:  results/pilot/alerts.csv        (true positive that tu lan quet goc)
      results/real_fp/real_fp_alerts.json  (false positive that, tu buoc 1)
Ghi:  results/real_eval/*.json        (khong de len bat cu file cu nao)

Phan TF-IDF va heuristic chay bang CPU. Phan LLM can GROQ_API_KEY.
Dat P09_SKIP_LLM=1 de chay truoc phan CPU va xem ket qua ngay.
"""
import csv, json, os, random, sys, time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "real_eval"; OUT.mkdir(parents=True, exist_ok=True)
SEED = 42
SKIP_LLM = os.getenv("P09_SKIP_LLM", "0") == "1"
MODEL = os.getenv("P09_MODEL", "openai/gpt-oss-20b")
RPM = float(os.getenv("GROQ_RPM", "20"))
IMB_RATIO = float(os.getenv("P09_IMB_RATIO", "6"))  # so FP tren moi TP


def load_tp():
    p = ROOT / "results" / "pilot" / "alerts.csv"
    rows = []
    with open(p, encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append({"rel_path": r.get("file_path") or r.get("rel_path", ""),
                         "line": int(r.get("start_line") or r.get("line") or 0),
                         "rule_id": r.get("rule_id", ""),
                         "msg": r.get("message") or r.get("msg", ""),
                         "label": "True Positive"})
    return rows


def load_fp():
    p = ROOT / "results" / "real_fp" / "real_fp_alerts.json"
    if not p.exists():
        raise SystemExit("Chua co real_fp_alerts.json - chay fix1_real_fp_scan.py truoc")
    return json.loads(p.read_text(encoding="utf-8"))


def heuristic(alert):
    """Bo loc regex thu cong, giu nguyen tinh than cua baseline cu."""
    m = (alert["msg"] or "").lower()
    r = (alert["rule_id"] or "").lower()
    for k in ("test", "example", "mock", "sample"):
        if k in (alert["rel_path"] or "").lower():
            return "reject"
    if any(k in r for k in ("hardcoded", "clear-text", "weak")):
        return "accept"
    if "may" in m or "could" in m:
        return "reject"
    return "accept"


def tfidf_cv(rows, folds=5, msg_only=False):
    """TF-IDF + RandomForest, 5-fold stratified. Chay tren CA HAI tap."""
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import StratifiedKFold
    import numpy as np
    X = [(r["msg"] if msg_only else f"{r['rule_id']} {r['msg']}") for r in rows]
    y = np.array([1 if r["label"] == "True Positive" else 0 for r in rows])
    pred = np.zeros(len(y), dtype=int)
    skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED)
    for tr, te in skf.split(X, y):
        v = TfidfVectorizer(ngram_range=(1, 2), min_df=1)
        Xtr = v.fit_transform([X[i] for i in tr])
        Xte = v.transform([X[i] for i in te])
        clf = RandomForestClassifier(n_estimators=200, random_state=SEED, n_jobs=1)
        clf.fit(Xtr, y[tr])
        pred[te] = clf.predict(Xte)
    return ["accept" if p == 1 else "reject" for p in pred]


SYS = ("You triage static-analysis alerts. Answer with exactly one word: "
       "accept if the alert is a real vulnerability, reject if it is a false positive.")


def llm_triage(rows, tag):
    """Ghi tung phan doan vao jsonl, chay lai duoc tu giua chung."""
    import requests
    key = os.getenv("GROQ_API_KEY")
    if not key:
        raise SystemExit("Thieu GROQ_API_KEY")
    cache_path = OUT / f"llm_cache_{tag}_nopath.jsonl"
    cache = {}
    if cache_path.exists():
        for line in cache_path.open(encoding="utf-8"):
            if line.strip():
                d = json.loads(line); cache[d["key"]] = d["verdict"]
        print(f"    (chay tiep: da co {len(cache)} phan doan tu lan truoc)")
    url = "https://api.groq.com/openai/v1/chat/completions"
    gap = 60.0 / RPM
    out, last = [], 0.0
    cf = cache_path.open("a", encoding="utf-8")
    for i, r in enumerate(rows, 1):
        ckey = f"{r['rel_path']}|{r['line']}|{r['rule_id']}"
        if ckey in cache:
            out.append(cache[ckey]); continue
        wait = gap - (time.time() - last)
        if wait > 0:
            time.sleep(wait)
        # KHONG gui duong dan file. Duong dan cua false positive nam trong
        # thu muc ten "Secure"/"FP", gui di la noi thang dap an cho model.
        # Ca TF-IDF va LLM deu chi thay rule_id + message.
        user = (f"Rule: {r['rule_id']}\nLine: {r['line']}\n"
                f"Message: {r['msg']}\n\naccept or reject?")
        verdict = "unclear"
        for attempt in range(6):
            try:
                resp = requests.post(url, timeout=60,
                    headers={"Authorization": f"Bearer {key}"},
                    json={"model": MODEL, "temperature": 0.0, "max_tokens": 1024,
                          "reasoning_effort": "low",
                          "messages": [{"role": "system", "content": SYS},
                                       {"role": "user", "content": user}]})
                last = time.time()
                if resp.status_code == 429:
                    time.sleep(min(60, 5 * (attempt + 1))); continue
                resp.raise_for_status()
                t = resp.json()["choices"][0]["message"]["content"].strip().lower()
                if "accept" in t: verdict = "accept"
                elif "reject" in t: verdict = "reject"
                break
            except Exception:
                time.sleep(5)
        out.append(verdict)
        cf.write(json.dumps({"key": ckey, "verdict": verdict}) + "\n"); cf.flush()
        if i % 20 == 0 or i == 1:
            print(f"    [{i}/{len(rows)}] {verdict}")
    cf.close()
    return out



def _mcc_from_counts(tp, fp, tn, fn):
    import math
    den = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    return ((tp*tn - fp*fn)/den) if den else 0.0


def _counts(labels, verdicts, idx=None):
    tp = fp = tn = fn = unc = 0
    rng_idx = range(len(labels)) if idx is None else idx
    for i in rng_idx:
        real, v = labels[i], verdicts[i]
        if v == "unclear":
            unc += 1; continue
        if v == "accept" and real: tp += 1
        elif v == "accept" and not real: fp += 1
        elif v == "reject" and not real: tn += 1
        else: fn += 1
    return tp, fp, tn, fn, unc


def boot_mcc(labels, verdicts, n_boot=5000, seed=SEED):
    """Khoang tin cay bootstrap cho MCC. Lay mau lai theo alert."""
    r = random.Random(seed)
    n = len(labels)
    vals = []
    for _ in range(n_boot):
        idx = [r.randrange(n) for _ in range(n)]
        vals.append(_mcc_from_counts(*_counts(labels, verdicts, idx)[:4]))
    vals.sort()
    return round(vals[int(0.025*n_boot)], 4), round(vals[int(0.975*n_boot)-1], 4)


def mcnemar(labels, va, vb):
    """So sanh tung cap hai bo phan loai tren cung tap alert.

    b = a dung / b sai, c = a sai / b dung. Dung nhi thuc chinh xac hai phia.
    """
    import math
    b = c = 0
    for real, x, y in zip(labels, va, vb):
        ok_x = (x == "accept") == real
        ok_y = (y == "accept") == real
        if ok_x and not ok_y: b += 1
        elif ok_y and not ok_x: c += 1
    n = b + c
    if n == 0:
        return {"b": 0, "c": 0, "p": 1.0}
    k = min(b, c)
    p = 0.0
    for i in range(0, k+1):
        p += math.comb(n, i) * 0.5**n
    p = min(1.0, 2*p)
    return {"b": b, "c": c, "p": float(f"{p:.6g}")}


def metrics(rows, verdicts, name):
    import math
    tp = fp = tn = fn = unc = 0
    for r, v in zip(rows, verdicts):
        real = r["label"] == "True Positive"
        if v == "unclear":
            unc += 1; continue
        if v == "accept" and real: tp += 1
        elif v == "accept" and not real: fp += 1
        elif v == "reject" and not real: tn += 1
        else: fn += 1
    den = math.sqrt((tp+fp)*(tp+fn)*(tn+fp)*(tn+fn))
    mcc = ((tp*tn - fp*fn)/den) if den else 0.0
    n = len(rows)
    labels = [r["label"] == "True Positive" for r in rows]
    lo, hi = boot_mcc(labels, verdicts)
    return {"triager": name, "n": n, "tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "unclear": unc, "mcc": round(mcc, 4),
            "mcc_ci_lo": lo, "mcc_ci_hi": hi,
            "accuracy": round((tp+tn)/max(1, n-unc), 4),
            "burden_fp_plus_50fn": fp + 50*fn + 50*unc,
            "_labels": labels, "_verdicts": list(verdicts)}


def main():
    print("=" * 66); print("BAI 09 - BUOC 2: dung lai tap danh gia tu du lieu THAT"); print("=" * 66)
    tp, fp = load_tp(), load_fp()
    print(f"\nTrue positive that : {len(tp)}")
    print(f"False positive that: {len(fp)}  ({len(set(r['rule_id'] for r in fp))} rule, "
          f"{len(set(r['msg'] for r in fp))} message)")

    # Chan doan ro ri: neu tap rule cua TP va FP roi nhau thi mot bo phan loai
    # chi can nho rule_id la thang, va con so do khong noi gi ve nang luc triage.
    rt = set(r["rule_id"] for r in tp)
    rf = set(r["rule_id"] for r in fp)
    shared = rt & rf
    print(f"\nRule cua TP: {len(rt)} | rule cua FP: {len(rf)} | trung nhau: {len(shared)}")
    if not shared:
        print("  [CANH BAO] Hai tap KHONG dung chung rule nao. Bat cu bo phan loai")
        print("  nao nhin thay rule_id deu co the thang bang cach nho rule, khong")
        print("  phai bang nang luc. Doc ky cot tfidf_msgonly truoc khi ket luan.")

    rng = random.Random(SEED)
    # Tap can bang: dung HET lop nho hon, khong chan cung o 20.
    n_bal = min(len(tp), len(fp))
    bal = rng.sample(tp, n_bal) + rng.sample(fp, n_bal)
    # Tap mat can bang: dung HET false positive, ha so true positive xuong
    # de dat ty le muc tieu. Nhu vay moi tap deu dung het lop gioi han no.
    n_imb_fp = len(fp)
    n_imb_tp = max(5, min(len(tp), round(n_imb_fp / IMB_RATIO)))
    imb = rng.sample(tp, n_imb_tp) + rng.sample(fp, n_imb_fp)
    rng.shuffle(bal); rng.shuffle(imb)
    print(f"\nTap can bang   : {len(bal)}  ({n_bal} TP : {n_bal} FP)")
    print(f"Tap mat can bang: {len(imb)}  ({n_imb_tp} TP : {n_imb_fp} FP, "
          f"ty le 1:{n_imb_fp/n_imb_tp:.1f})")
    print(f"Tong so lan goi LLM toi da: {len(bal) + len(imb)} "
          f"(da co trong cache thi khong goi lai)")

    results = []
    for setname, rows in (("balanced", bal), ("imbalanced", imb)):
        print(f"\n--- {setname} ---")
        results.append({**metrics(rows, ["accept"]*len(rows), "accept_all"), "set": setname})
        results.append({**metrics(rows, [heuristic(r) for r in rows], "heuristic"), "set": setname})
        print("  TF-IDF + RandomForest (nhanh bai cu KHONG chay tren imbalanced) ...")
        results.append({**metrics(rows, tfidf_cv(rows), "tfidf_rf"), "set": setname})
        print("  TF-IDF chi dung message, bo rule_id ...")
        results.append({**metrics(rows, tfidf_cv(rows, msg_only=True),
                                  "tfidf_msgonly"), "set": setname})
        if not SKIP_LLM:
            print(f"  LLM ({MODEL}) tren {len(rows)} alert ...")
            results.append({**metrics(rows, llm_triage(rows, setname), "llm"), "set": setname})

    # So sanh tung cap tren cung tap alert (McNemar chinh xac)
    pairs = {}
    for setname in ("balanced", "imbalanced"):
        got = {r["triager"]: r for r in results if r["set"] == setname}
        labels = next((r["_labels"] for r in got.values()), None)
        if labels is None:
            continue
        names = [k for k in ("accept_all", "heuristic", "tfidf_rf",
                             "tfidf_msgonly", "llm") if k in got]
        for i in range(len(names)):
            for j in range(i + 1, len(names)):
                a, b = names[i], names[j]
                pairs[f"{setname}:{a}_vs_{b}"] = mcnemar(
                    labels, got[a]["_verdicts"], got[b]["_verdicts"])

    clean = [{k: v for k, v in r.items() if not k.startswith("_")} for r in results]
    (OUT / "real_eval_results.json").write_text(json.dumps(
        {"config": {"seed": SEED, "model": MODEL, "n_tp": len(tp), "n_fp": len(fp),
                    "n_balanced": len(bal), "n_imbalanced": len(imb),
                    "imb_ratio": round(n_imb_fp / n_imb_tp, 3),
                    "n_rules_fp": len(set(r["rule_id"] for r in fp)),
                    "n_messages_fp": len(set(r["msg"] for r in fp)),
                    "boot": 5000,
                    "n_rules_tp": len(rt), "n_rules_shared": len(shared),
                    "rules_shared": sorted(shared)},
         "balanced": [r for r in clean if r["set"] == "balanced"],
         "imbalanced": [r for r in clean if r["set"] == "imbalanced"],
         "mcnemar": pairs},
        indent=2), encoding="utf-8")

    print("\n" + "=" * 78)
    print(f"{'set':11s} {'triager':12s} {'n':>4s} {'MCC':>8s} {'95% CI':>18s} "
          f"{'acc':>7s} {'burden':>7s}")
    for r in results:
        ci = f"[{r['mcc_ci_lo']:.3f}, {r['mcc_ci_hi']:.3f}]"
        print(f"{r['set']:11s} {r['triager']:12s} {r['n']:4d} {r['mcc']:8.4f} "
              f"{ci:>18s} {r['accuracy']:7.4f} {r['burden_fp_plus_50fn']:7d}")

    print("\n--- McNemar tung cap (b = chi cai dau dung, c = chi cai sau dung) ---")
    for k, v in pairs.items():
        print(f"  {k:42s} b={v['b']:3d} c={v['c']:3d} p={v['p']:.3e}")
    print(f"\nDa ghi -> {OUT / 'real_eval_results.json'}")
    print("\nCAU HOI QUYET DINH: TF-IDF tren tap mat can bang co thang LLM khong?")
    print("Neu co thi tieu de bai bao phai doi.")


if __name__ == "__main__":
    main()
