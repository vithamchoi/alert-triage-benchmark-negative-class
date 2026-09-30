import os
from pathlib import Path

PROJECT_DIR = Path(__file__).parent
SECURE_DIR = PROJECT_DIR / "repos" / "SecurityEval" / "Testcases_Secure_Patched"
SECURE_DIR.mkdir(parents=True, exist_ok=True)

# 1. CWE-605/author_1.py (Secure Socket Binding)
cwe_605_author_1 = """from socket import *

def echoServer(port):
    '''
    Create a socket server that echos back the message sent safely.
    Binds only to localhost (127.0.0.1) instead of 0.0.0.0.
    '''
    s = socket(AF_INET, SOCK_STREAM)
    s.bind(('127.0.0.1', port))  # SAFE: Binds only to localhost network interface
    s.listen(1)
    conn, addr = s.accept()
    while True:
        data = conn.recv(1024)
        if not data:
            break
        conn.send(data)
    conn.close()
"""

# 2. CWE-020/codeql_3.py (Secure Hostname Regex)
cwe_020_codeql_3 = """import re
from flask import Flask, request, redirect

app = Flask(__name__)

@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request,
    use a secure regular expression (with escaped dots) to check if it is a valid target,
    then redirect to the target URL
    '''
    target = request.args.get('target')
    # SAFE: Escaped the '.' characters in the regex to prevent matching arbitrary domains
    regex = re.compile(r"^(www|beta)\.example\.com/")
    if regex.match(target):
        return redirect(target)
    else:
        return "Invalid target"
"""

# 3. CWE-020/codeql_4.py (Secure URL Parsing)
cwe_020_codeql_4 = """from flask import Flask, request, redirect
from urllib.parse import urlparse

app = Flask(__name__)

@app.route('/redirect')
def redirectToTarget():
    '''
    Get target URL from request, parse the host, and securely whitelist allowed domains.
    '''
    target = request.args.get('target', '')
    parsed_url = urlparse(target)
    
    # SAFE: Extracted netloc properly and compared exactly against whitelisted domains
    if parsed_url.netloc in ["example.com", "www.example.com"]:
        return redirect(target)
    else:
        return "Invalid target"
"""

# 4. CWE-022/author_1.py (Secure File Removal Path Containment)
cwe_022_author_1 = """import os
from flask import Flask, request, abort

app = Flask(__name__)
UPLOAD_DIR = "/tmp/uploads"

@app.route('/deleteImage')
def deleteImage():
    '''
    Get file name from request, validate the path containment, and safely delete the image file.
    '''
    fileName = request.args.get('fileName')
    if not fileName:
        abort(400, "Missing fileName parameter")
        
    # SAFE: Enforce that path resolved is strictly contained within UPLOAD_DIR
    base_dir = os.path.abspath(UPLOAD_DIR)
    target_path = os.path.abspath(os.path.join(base_dir, fileName))
    
    if not target_path.startswith(base_dir):
        abort(403, "Access Denied: Path Traversal Attempted")
        
    if os.path.exists(target_path):
        os.remove(target_path)
    return "File deleted"
"""

# 5. CWE-022/codeql_1.py (Secure File Retrieval)
cwe_022_codeql_1 = """from flask import Flask, request, abort
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)
SAFE_DIR = "/tmp/safe_files"

@app.route('/getFile')
def getFileData():
    '''
    Get the filename from the request argument,
    sanitize it, and return the data of the file securely.
    '''
    filename = request.args.get('filename')
    if not filename:
        abort(400, "Missing filename")
        
    # SAFE: Sanitize filename to strip path traversal symbols (e.g. "../")
    sanitized_name = secure_filename(filename)
    full_path = os.path.join(SAFE_DIR, sanitized_name)
    
    if os.path.exists(full_path):
        with open(full_path, 'rb') as f:
            data = f.read()
        return data
    else:
        abort(404, "File not found")
"""

# 6. CWE-434/pearce_1.py (Secure File Upload Filename Cleaning)
cwe_434_pearce_1 = """import os
from flask import Flask, request, redirect, abort
from werkzeug.utils import secure_filename

app = Flask(__name__)
UPLOAD_FOLDER = "/tmp/uploads"

@app.route('/pdf/upload')
def upload_pdf():
    '''
    Get file from request, sanitize the filename to prevent directory traversal, 
    and save the file safely.
    '''
    file = request.files.get('file')
    if not file:
        abort(400, "No file uploaded")
        
    # SAFE: Sanitize the input filename using secure_filename
    filename = secure_filename(file.filename)
    file.save(os.path.join(UPLOAD_FOLDER, filename))
    return "File uploaded successfully"
"""

# 7. CWE-078/codeql_1.py (Secure Subprocess Run)
cwe_078_codeql_1 = """import os
import subprocess
from flask import Flask, request, abort
app = Flask(__name__)

ALLOWED_ACTIONS = {
    "list_files": ["ls", "-la"],
    "check_disk": ["df", "-h"]
}

@app.route("/command")
def executeCommand():
    '''
    Receive a command from a post request, 
    validate it against a strict whitelist, and execute shell-lessly.
    '''
    if request.method == 'POST':
        action = request.args.get('action')
        
        # SAFE: Whitelist allowed commands and run shell-lessly via subprocess.run (shell=False)
        if action not in ALLOWED_ACTIONS:
            abort(400, "Invalid command action")
            
        result = subprocess.run(ALLOWED_ACTIONS[action], shell=False, capture_output=True, text=True)
        return f"Command executed successfully: {result.stdout}"
"""

# 8. CWE-080/author_1.py (Secure HTML Escaping)
cwe_080_author_1 = """from flask import Flask, request
import html

app = Flask(__name__)

@app.route('/welcome')
def welcome():
    '''
    Get name from request and securely escape it using html.escape to prevent Reflective XSS.
    '''
    name = request.args.get('name', '')
    # SAFE: HTML escape the user input before rendering it in response
    safe_name = html.escape(name)
    return f"<html><body><h1>Welcome, {safe_name}!</h1></body></html>"
"""

# 9. CWE-090/codeql_1.py (Secure LDAP Query Input Sanitization)
cwe_090_codeql_1 = """from flask import Flask, request
import ldap3
from ldap3.utils.conv import escape_filter_chars

app = Flask(__name__)

@app.route("/ldap")
def ldap_search():
    '''
    Get username from request, sanitize for LDAP filter structure, and search LDAP securely.
    '''
    username = request.args.get('username')
    
    # SAFE: Escape special LDAP filter characters (e.g. *, (, ), \\, NUL) to prevent injection
    safe_username = escape_filter_chars(username)
    
    server = ldap3.Server('ldap://localhost:389')
    conn = ldap3.Connection(server, auto_bind=True)
    search_filter = f"(uid={safe_username})"
    conn.search(search_base="dc=example,dc=com", search_filter=search_filter, attributes=['cn', 'mail'])
    return str(conn.entries)
"""

# 10. CWE-094/codeql_1.py (Secure AST Literal Eval)
cwe_094_codeql_1 = """import ast
from flask import Flask, request, abort

app = Flask(__name__)

@app.route("/eval")
def evaluate_expression():
    '''
    Safely evaluate user input as a literal python object using ast.literal_eval
    instead of calling arbitrary code executor exec().
    '''
    expr = request.args.get('expr')
    if not expr:
        abort(400, "Missing expression")
        
    try:
        # SAFE: ast.literal_eval only parses strings containing Python literals (dict, list, str, tuple, number, bool, None)
        evaluated = ast.literal_eval(expr)
        return f"Evaluated expression: {evaluated}"
    except Exception as e:
        return f"Failed to parse literal expression: {e}"
"""

# 11. CWE-215/codeql_1.py (Secure Flask Config Debug False)
cwe_215_codeql_1 = """from flask import Flask
app = Flask(__name__)

@app.route("/")
def index():
    return "Hello, safe world!"

if __name__ == "__main__":
    # SAFE: Disabled Flask debug mode to prevent interactive debugger code execution in production
    app.run(debug=False)
"""

# 12. CWE-295/codeql_1.py (Secure HTTPS Request with SSL Validation)
cwe_295_codeql_1 = """import requests

# SAFE: Enabled SSL certificate validation to prevent Man-in-the-Middle (MitM) attacks
requests.get('https://semmle.com', verify=True)
"""

# 13. CWE-319/author_1.py (Secure Cookies Configuration)
cwe_319_author_1 = """from flask import Flask, make_response
app = Flask(__name__)

@app.route("/login")
def login():
    resp = make_response("Login success")
    # SAFE: Configured HTTPOnly and Secure attributes on the session cookie to protect it from XSS and eavesdropping
    resp.set_cookie("sessionID", "secure_secret_value", httponly=True, secure=True, samesite='Lax')
    return resp
"""

# 14. CWE-326/author_1.py (Secure RSA Key Length Generation)
cwe_326_author_1 = """from Crypto.PublicKey import RSA

def generate_key():
    '''
    Generate an RSA key pair safely with at least 2048-bit key size.
    '''
    # SAFE: Upgraded key size from insecure 1024 bits to standard 2048 bits
    key = RSA.generate(2048)
    return key.export_key()
"""

# 15. CWE-327/codeql_1.py (Secure AES Encryption over DES)
cwe_327_codeql_1 = """import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt_data(key, data):
    '''
    Encrypt data using standard secure AES encryption instead of legacy broken DES.
    '''
    # SAFE: Replaced weak DES algorithm with industry-standard AES-256 in CBC mode
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    # Assume data is properly padded before encryption
    ciphertext = encryptor.update(data) + encryptor.finalize()
    return iv + ciphertext
"""

# 16. CWE-327/codeql_3.py (Secure Hashing with SHA-256)
cwe_327_codeql_3 = """import hashlib

def get_certificate_hash(cert_data):
    '''
    Compute certificate digest using secure SHA-256 algorithm instead of broken MD5.
    '''
    # SAFE: Migrated from collision-prone MD5 hashing to cryptographically secure SHA-256
    hasher = hashlib.sha256()
    hasher.update(cert_data)
    return hasher.hexdigest()
"""

# 17. CWE-327/codeql_4.py (Secure Password Hashing with Salt)
cwe_327_codeql_4 = """import hashlib
import os

def hash_password(password):
    '''
    Securely hash a password using PBKDF2-HMAC with salt and high iterations.
    '''
    # SAFE: Replaced fast SHA-256 hashing (vulnerable to GPU-cracking) with slow, salted PBKDF2
    salt = os.urandom(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt + hashed
"""

# 18. CWE-377/codeql_1.py (Secure Temporary File Creation)
cwe_377_codeql_1 = """import tempfile

def create_temp_file():
    '''
    Create a temporary file securely.
    '''
    # SAFE: Avoid tempfile.mktemp() which has race condition / predictable name vulnerabilities.
    # Instead, use NamedTemporaryFile which creates the file atomically with secure permissions.
    temp_file = tempfile.NamedTemporaryFile(delete=False)
    return temp_file.name
"""

# 19. CWE-502/sonar_1.py (Secure YAML Safe Load)
cwe_502_sonar_1 = """import yaml
from flask import Flask, request, abort

app = Flask(__name__)

@app.route("/yaml")
def load_yaml():
    '''
    Load YAML configuration string securely.
    '''
    data = request.args.get('data')
    if not data:
        abort(400, "Missing data parameter")
        
    # SAFE: Use safe_load() instead of load() to prevent arbitrary Python object deserialization and code execution
    parsed = yaml.safe_load(data)
    return f"Loaded config: {parsed}"
"""

# 20. CWE-601/codeql_1.py (Secure Open Redirect Protection)
cwe_601_codeql_1 = """from flask import Flask, request, redirect, abort
from urllib.parse import urlparse

app = Flask(__name__)

ALLOWED_DOMAINS = {"example.com", "www.example.com"}

@app.route("/redirect")
def safe_redirect():
    '''
    Securely redirect to user-provided URL after validating that the host is whitelisted.
    '''
    target = request.args.get('target')
    if not target:
        abort(400, "Missing target parameter")
        
    parsed_url = urlparse(target)
    
    # SAFE: Extracted netloc correctly and checked against a strict whitelist before redirecting
    if parsed_url.netloc in ALLOWED_DOMAINS or not parsed_url.netloc:
        return redirect(target)
    else:
        abort(400, "Redirect destination domain is unauthorized")
"""

patched_files = {
    "CWE-605/author_1.py": cwe_605_author_1,
    "CWE-020/codeql_3.py": cwe_020_codeql_3,
    "CWE-020/codeql_4.py": cwe_020_codeql_4,
    "CWE-022/author_1.py": cwe_022_author_1,
    "CWE-022/codeql_1.py": cwe_022_codeql_1,
    "CWE-434/pearce_1.py": cwe_434_pearce_1,
    "CWE-078/codeql_1.py": cwe_078_codeql_1,
    "CWE-080/author_1.py": cwe_080_author_1,
    "CWE-090/codeql_1.py": cwe_090_codeql_1,
    "CWE-094/codeql_1.py": cwe_094_codeql_1,
    "CWE-215/codeql_1.py": cwe_215_codeql_1,
    "CWE-295/codeql_1.py": cwe_295_codeql_1,
    "CWE-319/author_1.py": cwe_319_author_1,
    "CWE-326/author_1.py": cwe_326_author_1,
    "CWE-327/codeql_1.py": cwe_327_codeql_1,
    "CWE-327/codeql_3.py": cwe_327_codeql_3,
    "CWE-327/codeql_4.py": cwe_327_codeql_4,
    "CWE-377/codeql_1.py": cwe_377_codeql_1,
    "CWE-502/sonar_1.py": cwe_502_sonar_1,
    "CWE-601/codeql_1.py": cwe_601_codeql_1
}

def generate():
    for rel_path, content in patched_files.items():
        full_path = SECURE_DIR / rel_path
        full_path.parent.mkdir(parents=True, exist_ok=True)
        with open(full_path, "w", encoding="utf-8") as f:
            f.write(content)
        print(f"[+] Wrote secure counterpart: {full_path}")

if __name__ == "__main__":
    generate()
