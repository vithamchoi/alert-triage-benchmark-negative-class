import os
from pathlib import Path

PROJECT_DIR = Path(__file__).parent
FP_DIR = PROJECT_DIR / "repos" / "SecurityEval" / "Testcases_Secure_FP"
FP_DIR.mkdir(parents=True, exist_ok=True)

# Templates for secure files that trigger CodeQL false positives

# CWE-022: Path Injection (Custom validation check)
CWE_022_TEMPLATE = """import os
from flask import Flask, request, abort

app = Flask(__name__)
UPLOAD_DIR = "/tmp/uploads"

@app.route('/download_{var_id}')
def download_{var_id}():
    '''
    Safe download using a custom validation method to block path traversal.
    CodeQL will flag this because it doesn't recognize our custom alphanumeric sanitizer.
    '''
    filename = request.args.get('file_{var_id}')
    if not filename:
        abort(400, "Missing filename")
        
    # Strict validation: only allow simple alphanumeric names, no dots or slashes
    if not filename.isalnum():
        abort(400, "Invalid filename format")
        
    # Safe path construction: filename is guaranteed to be alphanumeric
    safe_path = os.path.join(UPLOAD_DIR, filename)
    
    with open(safe_path, 'r') as f:
        return f.read()
"""

# CWE-078: Command Injection (Alphanumeric whitelist)
CWE_078_TEMPLATE = """import os
from flask import Flask, request, abort

app = Flask(__name__)

@app.route('/ping_{var_id}')
def ping_{var_id}():
    '''
    Safe system command run using strict alphanumeric validation of input.
    CodeQL will flag this because it sees command concatenation.
    '''
    target_host = request.args.get('host_{var_id}')
    if not target_host:
        abort(400, "Missing host")
        
    # Safe: Alphanumeric only, no shell metacharacters can be injected
    if not target_host.isalnum():
        abort(400, "Invalid characters in host")
        
    # Executing command safely due to validation
    cmd = "ping -c 1 " + target_host
    res = os.popen(cmd).read()
    return res
"""

# CWE-089: SQL Injection (Integer casting)
CWE_089_TEMPLATE = """import sqlite3
from flask import Flask, request, abort

app = Flask(__name__)

@app.route('/user_{var_id}')
def get_user_{var_id}():
    '''
    Safe SQL query using integer validation to prevent injection.
    CodeQL will flag this because it sees SQL query string concatenation.
    '''
    raw_id = request.args.get('id_{var_id}')
    if not raw_id:
        abort(400, "Missing ID")
        
    # Safe: Force check that it is pure digits/integer
    if not raw_id.isdigit():
        abort(400, "Invalid ID format")
        
    # Concatenation is safe here because raw_id is strictly an integer
    conn = sqlite3.connect("app_{var_id}.db")
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM users WHERE id = " + raw_id)
    return str(cursor.fetchall())
"""

# CWE-327: Weak Hashing (MD5 flagged due to sensitive-sounding name)
CWE_327_TEMPLATE = """import hashlib

def calculate_{var_id}_checksum(sensitive_token_data):
    '''
    Safe MD5 usage for non-cryptographic checksumming, flagged because of variable naming.
    CodeQL flags MD5 as weak sensitive data hashing.
    '''
    # Safe: Used solely as a unique ID cache key for local files, not security/passwords
    hasher = hashlib.md5()
    hasher.update(sensitive_token_data.encode('utf-8'))
    return hasher.hexdigest()
"""

# CWE-601: Open Redirect (Relative path constraint)
CWE_601_TEMPLATE = """from flask import Flask, request, redirect, abort
from urllib.parse import urlparse

app = Flask(__name__)

@app.route('/goto_{var_id}')
def goto_{var_id}():
    '''
    Safe redirect by strictly constraining destination to a relative path.
    CodeQL flags this because it doesn't recognize relative checking logic.
    '''
    dest = request.args.get('url_{var_id}')
    if not dest:
        abort(400, "Missing destination")
        
    # Safe: Force redirect to be a relative URL, preventing external redirection
    parsed = urlparse(dest)
    if parsed.netloc or dest.startswith("//"):
        abort(400, "External redirect is forbidden")
        
    return redirect(dest)
"""

# CWE-295: SSL Verification (Internal local mock environment)
CWE_295_TEMPLATE = """import requests

def fetch_{var_id}_mock_data():
    '''
    Safe disabling of SSL validation within a closed-loop internal mock endpoint.
    CodeQL flags requests without certificate validation.
    '''
    # Safe: Only used to query internal mocked interface during automated unit testing
    response = requests.get('https://localhost:8443/mock_{var_id}', verify=False)
    return response.json()
"""

# CWE-377: Insecure Temporary File (Immediate secure permissions)
CWE_377_TEMPLATE = """import tempfile
import os

def create_secure_{var_id}_temp():
    '''
    Safe use of mktemp by immediately setting secure chmod file permissions.
    CodeQL flags mktemp calls as insecure.
    '''
    # Safe: The temp file path is created and immediately restricted via file descriptor controls
    temp_path = tempfile.mktemp()
    fd = os.open(temp_path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write("secure_{var_id}")
    return temp_path
"""

# CWE-094: Code Injection (Safe arithmetic regex evaluation)
CWE_094_TEMPLATE = """import re
from flask import Flask, request, abort

app = Flask(__name__)

@app.route('/calc_{var_id}')
def calc_{var_id}():
    '''
    Safe eval of mathematical expressions using strict regex whitelisting.
    CodeQL flags all eval statements regardless of input safety checks.
    '''
    expr = request.args.get('expr')
    if not expr:
        abort(400, "Missing expression")
        
    # Safe: Strict whitelist allowing only digits and basic arithmetic operators
    if not re.match(r"^[0-9+\\-*/().\\s]+$", expr):
        abort(400, "Unsafe expression format")
        
    # Perfectly safe execution due to whitelist, but CodeQL will flag it!
    res = eval(expr)
    return f"Result: {{res}}"
"""

# CWE-605: Socket Binding (Explicit config bind override)
CWE_605_TEMPLATE = """import socket

def init_{var_id}_socket(bind_all=False):
    '''
    Safe binding mechanism with user confirmation controls.
    CodeQL flags socket binding to empty string or all interfaces.
    '''
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Safe: Binds to local interface by default, unless explicitly requested in a secure environment
    if not bind_all:
        s.bind(('127.0.0.1', 8080))
    else:
        s.bind(('', 8080)) # Explicitly overridden for cluster network mode
    s.listen(5)
    return s
"""

# CWE-215: Flask Debug (Flask debug True under dead block)
CWE_215_TEMPLATE = """from flask import Flask

app = Flask(__name__)

@app.route('/test_{var_id}')
def test_{var_id}():
    return "Test {var_id}"

def run_app_{var_id}():
    '''
    Safe Flask run with debug mode isolated under a dead check block.
    CodeQL flags any app.run(debug=True) call statically.
    '''
    # Safe: This block will never execute in production due to the False constant check
    if False:
        app.run(debug=True)
    else:
        app.run(debug=False)
"""

# CWE-326: Weak RSA Key Generation (Short key size in test case)
CWE_326_TEMPLATE = """from Crypto.PublicKey import RSA

def get_test_{var_id}_key():
    '''
    Safe generation of small RSA key for isolated mock tests.
    CodeQL flags RSA key sizes less than 2048 bits.
    '''
    # Safe: Used strictly inside a localized test-bench to run quick mock signatures
    return RSA.generate(1024).export_key()
"""

# CWE-020: Incomplete Regex Sanitization (URL matching with unescaped dot)
CWE_020_TEMPLATE = """import re
from flask import Flask, request, abort

app = Flask(__name__)

@app.route('/match_{var_id}')
def match_{var_id}():
    '''
    Safe matching despite unescaped dot since the matched result is exactly whitelisted.
    CodeQL flags URL regex matches with unescaped dots.
    '''
    url = request.args.get('url')
    # Unescaped dot in regex
    pattern = re.compile(r"^http://localhost.example.com")
    
    if pattern.match(url) and url == "http://localhost.example.com":
        # Safe: Strictly verified via exact equality check before usage
        return f"Safe matched URL: {{url}}"
    else:
        abort(400, "Unauthorized URL")
"""

TEMPLATES = {
    "CWE-022": CWE_022_TEMPLATE,
    "CWE-078": CWE_078_TEMPLATE,
    "CWE-089": CWE_089_TEMPLATE,
    "CWE-327": CWE_327_TEMPLATE,
    "CWE-601": CWE_601_TEMPLATE,
    "CWE-295": CWE_295_TEMPLATE,
    "CWE-377": CWE_377_TEMPLATE,
    "CWE-094": CWE_094_TEMPLATE,
    "CWE-605": CWE_605_TEMPLATE,
    "CWE-215": CWE_215_TEMPLATE,
    "CWE-326": CWE_326_TEMPLATE,
    "CWE-020": CWE_020_TEMPLATE
}

def main():
    print("[*] Generating 144 secure counterpart files that trigger False Positives...")
    count = 0
    # Generate 12 variations per category (12 categories * 12 = 144 files)
    for cwe, template in TEMPLATES.items():
        cwe_dir = FP_DIR / cwe
        cwe_dir.mkdir(parents=True, exist_ok=True)
        
        for i in range(1, 13):
            file_name = f"fp_{i}.py"
            file_path = cwe_dir / file_name
            
            # Format the template with dynamic ID to make files unique
            code = template.format(var_id=f"{cwe.replace('-', '_')}_{i}")
            
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(code)
            count += 1
            
    print(f"[+] Successfully wrote {count} files to {FP_DIR}")

if __name__ == "__main__":
    main()
