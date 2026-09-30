"""Bai 09, buoc 1: quet CodeQL de lay FALSE POSITIVE THAT.

Van de: results/fp_alerts.json hien tai la 120 file tong hop (10 rule x 12 ban
sao, 1 chuoi message duy nhat). Lan quet that ra 59 TP va 0 FP.

Cach sua: SecurityEval co san hai thu muc code AN TOAN:
    Testcases_Secure_FP       - code an toan, co tinh viet de trong giong loi
    Testcases_Secure_Patched  - code da duoc va loi
Bat ky alert nao CodeQL bao tren hai thu muc do deu la FALSE POSITIVE THAT,
vi tac gia SecurityEval chung nhan code do an toan. Khong can bia.

Ghi ra results/real_fp/ , khong de len file cu.
"""
import json, os, shutil, stat, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "results" / "real_fp"
OUT.mkdir(parents=True, exist_ok=True)
CODEQL = os.getenv("CODEQL_BIN", r"C:\codeql_cli\codeql\codeql.exe")

SOURCES = [
    ("secure_fp", ROOT / "repos" / "SecurityEval" / "Testcases_Secure_FP"),
    ("secure_patched", ROOT / "repos" / "SecurityEval" / "Testcases_Secure_Patched"),
]


def suite():
    roots = [Path(CODEQL).parent, Path(CODEQL).parent.parent, ROOT.parent / "codeql"]
    for r in roots:
        m = sorted(r.glob("qlpacks/codeql/python-queries/*/codeql-suites/"
                          "python-security-extended.qls"))
        if m:
            return str(m[-1])
    return "python-security-extended.qls"


def rmtree(p):
    if p.exists():
        shutil.rmtree(p, onerror=lambda f, path, e: (os.chmod(path, stat.S_IWRITE), f(path)))


def run(cmd):
    print("  $", " ".join(str(c) for c in cmd)[:150])
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout[-2000:]); print(r.stderr[-2000:])
        raise SystemExit(f"CodeQL that bai (ma loi {r.returncode})")


def parse(sarif_path, label):
    sarif = json.loads(Path(sarif_path).read_text(encoding="utf-8"))
    rows = []
    for run_ in sarif.get("runs", []):
        for res in run_.get("results", []):
            rule = res.get("ruleId", "")
            msg = (res.get("message") or {}).get("text", "")
            for loc in res.get("locations", []) or []:
                pl = (loc.get("physicalLocation") or {})
                art = (pl.get("artifactLocation") or {}).get("uri", "")
                line = (pl.get("region") or {}).get("startLine", 0)
                rows.append({"rel_path": art, "line": line, "rule_id": rule,
                             "msg": msg, "source": label, "label": "False Positive"})
    return rows


def main():
    print("=" * 66)
    print("BAI 09 - BUOC 1: quet CodeQL lay false positive THAT")
    print("=" * 66)
    allrows = []
    for label, src in SOURCES:
        if not src.exists():
            print(f"[!] Bo qua, khong thay {src}")
            continue
        sarif = OUT / f"{label}.sarif"
        if sarif.exists() and sarif.stat().st_size > 0:
            # CHAY TIEP: lan truoc da quet xong nguon nay roi
            rows = parse(sarif, label)
            print(f"\n[{label}] da quet tu lan truoc -> {len(rows)} alert, bo qua")
            allrows += rows
            continue
        n_py = len(list(src.rglob("*.py")))
        print(f"\n[{label}] {n_py} file .py trong {src.name}")
        db = OUT / f"db_{label}"
        rmtree(db)
        run([CODEQL, "database", "create", str(db), "--language=python",
             f"--source-root={src}", "--overwrite"])
        run([CODEQL, "database", "analyze", str(db), suite(),
             "--format=sarif-latest", f"--output={sarif}"])
        rows = parse(sarif, label)
        print(f"  -> {len(rows)} alert (deu la FALSE POSITIVE that)")
        allrows += rows
        rmtree(db)
        # ghi ngay sau moi nguon, phong khi tat may giua chung
        (OUT / f"partial_{label}.json").write_text(
            json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    uniq = {}
    for r in allrows:
        uniq[(r["rel_path"], r["line"], r["rule_id"])] = r
    rows = list(uniq.values())
    (OUT / "real_fp_alerts.json").write_text(
        json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")

    import collections
    print("\n" + "=" * 66)
    print(f"Tong: {len(rows)} false positive that, {len(set(r['rule_id'] for r in rows))} rule khac nhau")
    print(f"      {len(set(r['msg'] for r in rows))} chuoi message khac nhau")
    print("      (file cu: 120 alert, 10 rule, 1 message - do bia)")
    for rule, c in collections.Counter(r["rule_id"] for r in rows).most_common(10):
        print(f"      {c:4d}  {rule}")
    print(f"\nDa ghi -> {OUT / 'real_fp_alerts.json'}")
    if len(rows) < 40:
        print("\n[!] CANH BAO: duoi 40 FP that. Bai 09 se phai bao cao co mau nho")
        print("    hoac mo rong corpus. Dung bia them.")


if __name__ == "__main__":
    main()
