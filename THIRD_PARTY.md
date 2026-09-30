# Third-party code and data, not redistributed here

The experiments depend on the following. We link them rather than bundle them,
so that their own licences and versions govern.

| Component | Where | Used for |
|---|---|---|
| CodeQL CLI | github.com/github/codeql-cli-binaries | the static analyser |
| `python-security-extended` query suite | github.com/github/codeql | the queries that produced the alerts |
| SecurityEval | the benchmark our corpus is derived from | the source of the vulnerable and patched files |
| scikit-learn | scikit-learn.org | the TF-IDF triagers |

Record the version or commit of each before re-running; the scripts do not pin them.
