import os
import json
import time
import subprocess
import shutil
import stat
from pathlib import Path

PROJECT_DIR = Path(__file__).parent
TARGET_CODE_DIR = PROJECT_DIR / "repos" / "SecurityEval" / "Testcases_Secure_FP"
DB_PATH = PROJECT_DIR / "results" / "codeql_db_fp"
SARIF_PATH = PROJECT_DIR / "results" / "codeql_results_fp.sarif"
CODEQL_BIN = r"C:\codeql_cli\codeql\codeql.exe"

def run_command(cmd):
    print(f"[*] Running command: {' '.join(cmd)}")
    start_time = time.time()
    result = subprocess.run(cmd, capture_output=True, text=True)
    end_time = time.time()
    print(f"[*] Execution time: {end_time - start_time:.2f}s")
    print(f"[*] Exit code: {result.returncode}")
    if result.returncode != 0:
        print("--- STDERR ---")
        print(result.stderr)
        raise Exception(f"Command failed with exit code {result.returncode}")
    return result

def main():
    print(f"=== Running CodeQL on Secure FP Dataset ===")
    if DB_PATH.exists():
        print(f"[*] Removing existing database: {DB_PATH}")
        def remove_readonly(func, path, excinfo):
            os.chmod(path, stat.S_IWRITE)
            func(path)
        shutil.rmtree(DB_PATH, onerror=remove_readonly)
    
    cmd_create = [
        CODEQL_BIN, "database", "create", str(DB_PATH),
        "--language=python",
        f"--source-root={TARGET_CODE_DIR}",
        "--overwrite"
    ]
    run_command(cmd_create)

    cmd_analyze = [
        CODEQL_BIN, "database", "analyze", str(DB_PATH),
        "python-security-extended.qls",
        "--format=sarif-latest",
        f"--output={SARIF_PATH}"
    ]
    run_command(cmd_analyze)
    print(f"[+] CodeQL analysis completed. SARIF report: {SARIF_PATH}")

if __name__ == "__main__":
    main()
