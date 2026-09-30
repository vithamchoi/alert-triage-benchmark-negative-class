# A failed repair of an alert-triage benchmark

Result files, experiment scripts and LaTeX sources for the paper

> V. T. Le, S. X. Ha, N. N. Phien and T. Q. Nguyen,
> "We Fabricated a Negative Class Twice: A Failed Repair of a Static-Analysis Alert-Triage Benchmark",
> submitted to Empirical Software Engineering (Springer), 2026.

## What is in here

```
results/     the measured result files. Every number, table and figure in the
             paper is computed from these and from nothing else.
scripts/     the experiment code that produced those files.
latex/       the generators that read results/ and emit the table bodies and
             figures, plus the paper source they are substituted into.
```

## What you can reproduce, and what you cannot

**From this repository alone** you can regenerate every table, figure and
inline number in the paper:

```bash
pip install -r requirements.txt
cd latex
python3 make_tables.py  ../results  tables
python3 make_figures.py ../results  figures
python3 build.py        ../results          # writes main.tex
python3 build_ieee.py                      # writes ieee/main_ieee.tex
```

`build.py` substitutes the generated values into `paper_template.tex`. No number
in the paper is typed by hand, so a mismatch between the paper and a fresh run
of these scripts is a bug and we would like to hear about it.

`build_ieee.py` then rewrites that manuscript into the IEEE two-column form that
was actually submitted: it drops the CRediT section, which IEEE has no field for,
lifts the funding statement into a page-one footnote, rebuilds the author block
in IEEE style, and widens only the tables that overflow a column.
`latex/ieee/main_ieee.tex` is checked in even though it is generated, because it
is the exact manuscript we submitted. Regenerating it must produce the same
bytes; that diff is the artifact's own self-check, and we ran it on all nine
papers before publishing.

**You cannot regenerate `results/` from this repository alone.** Doing that needs
the CodeQL CLI, the `python-security-extended` query suite and a checkout of the SecurityEval benchmark. `fix1_real_fp_scan.py` is published unmodified, including a docstring that asserts the benchmark's authors certify two directories as secure. They do not exist upstream and nobody certifies them. The gap between what that script claims and what it does is the subject of the paper, so we did not clean it up.
The scripts in `scripts/` are the code we ran; they are published so the
procedure can be inspected and re-executed by anyone who assembles that
environment.

## Layout of `results/`

| File | Used for |
|---|---|
| `pilot/alerts.csv` | the true-positive alerts: rule, message, file, line |
| `real_fp/real_fp_alerts.json` | the false-positive alerts, each with the source corpus it came from |
| `real_fp/secure_fp.sarif` | the raw static-analysis output the false positives were extracted from |
| `real_fp/secure_patched.sarif` | the raw output of the second, patched directory |
| `real_fp/partial_secure_fp.json` | the partial extraction kept for the record |
| `real_fp/partial_secure_patched.json` | the partial extraction of the patched directory |
| `real_eval/real_eval_results.json` | per-triager confusion counts, bootstrap MCC intervals, burden, and the pairwise McNemar tests |
| `audit/audit_results.json` | the explanation-rubric items and the contamination probes |
| `fp_alerts.json` | the first, discarded false-positive set. The paper's title refers to it; it is published because the discarding is the finding |
| `evaluation/evaluation_results.json` | the first evaluation round, superseded |
| `evaluation_v2/v2_results.json` | the second evaluation round, superseded |
| `pilot/manual_labels.csv` | the hand labels used for the sanity check |
| `pilot/summary_report.md` | the pilot's own narrative report |

## Licence

Code in `scripts/` and `latex/` is MIT. The result files in `results/` are
CC BY 4.0. See `LICENSE`.
