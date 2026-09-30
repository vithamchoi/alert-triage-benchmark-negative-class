import os
import json
import csv
from pathlib import Path

PROJECT_DIR = Path(__file__).parent
SARIF_PATH = PROJECT_DIR / "results" / "codeql_results_fp.sarif"
OUTPUT_JSON = PROJECT_DIR / "results" / "fp_alerts.json"

def main():
    print("=== Parsing SARIF False Positive Alerts ===")
    if not SARIF_PATH.exists():
        print(f"[!] SARIF file not found at: {SARIF_PATH}")
        return
        
    with open(SARIF_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
        
    alerts = []
    for run in data.get("runs", []):
        for result in run.get("results", []):
            rule_id = result.get("ruleId")
            message = result.get("message", {}).get("text")
            locations = result.get("locations", [])
            if locations:
                loc = locations[0].get("physicalLocation", {})
                # Get the relative path from source root
                uri = loc.get("artifactLocation", {}).get("uri")
                region = loc.get("region", {})
                start_line = region.get("startLine", 1)
                
                # Normalize relative path to look like: "CWE-022/fp_1.py"
                # Since source root was Testcases_Secure_FP, the uri should be relative (e.g. CWE-022/fp_1.py)
                rel_path = uri.replace("\\", "/")
                if rel_path.startswith("CWE-"):
                    alerts.append({
                        "rel_path": rel_path,
                        "line": start_line,
                        "rule_id": rule_id,
                        "msg": message
                    })
                    
    print(f"[+] Parsed {len(alerts)} False Positive alerts.")
    
    # Save the parsed alerts
    with open(OUTPUT_JSON, "w", encoding="utf-8") as outf:
        json.dump(alerts, outf, indent=2)
    print(f"[+] Wrote parsed alerts to {OUTPUT_JSON}")
    
    # Show breakdown by CWE
    breakdown = {}
    for a in alerts:
        cwe = a["rel_path"].split("/")[0]
        breakdown[cwe] = breakdown.get(cwe, 0) + 1
        
    print("Breakdown by CWE:")
    for cwe, count in sorted(breakdown.items()):
        print(f"  - {cwe}: {count} alerts")

if __name__ == "__main__":
    main()
