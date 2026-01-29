import base64
import json
import os
from pathlib import Path

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class HermesPayloadType(PayloadType):
    name = "hermes"
    file_extension = "py"
    author = "@0xbbuddha"
    mythic_encrypts = True
    supported_os = [SupportedOS.Linux]
    wrapper = False
    wrapped_payloads = []
    note = """
Hermes - Agent Mythic C2 Linux-only, full Python.
Messenger god. Requires Python 3.8+ and pip install cryptography on target.
"""
    supports_dynamic_loading = False
    c2_profiles = ["http"]
    build_parameters = [
        BuildParameter(
            name="output_type",
            parameter_type=BuildParameterType.ChooseOne,
            description="Type de sortie",
            choices=["python", "zip"],
            default_value="python",
            required=False,
        ),
    ]
    agent_path = Path("agent_functions")
    agent_code_path = Path("agent_code")
    # Icon is in agent_functions directory (like Apollo)
    agent_icon_path = agent_path / "caduceus.svg"
    build_steps = [
        BuildStep(step_name="Gathering Files", step_description="Gathering agent files"),
        BuildStep(step_name="Injecting Config", step_description="Injecting C2 config and UUID"),
        BuildStep(step_name="Finalizing", step_description="Generating payload"),
    ]

    async def build(self) -> BuildResponse:
        build_stdout = ""
        build_stderr = ""

        try:
            # Check that C2 profiles are available
            if not hasattr(self, 'c2info') or not self.c2info or len(self.c2info) == 0:
                build_stderr += "ERROR: No C2 profile selected.\n"
                build_stderr += "\n"
                build_stderr += "SOLUTION:\n"
                build_stderr += "1. When creating the payload in Mythic, make sure to select the 'HTTP' C2 profile\n"
                build_stderr += "2. The HTTP profile must be enabled in your Mythic instance\n"
                build_stderr += "3. Verify that you have checked the HTTP profile in the payload creation interface\n"
                return BuildResponse(
                    status=BuildStatus.Error,
                    build_stdout=build_stdout,
                    build_stderr=build_stderr,
                )

            c2 = self.c2info[0]
            profile = c2.get_c2profile()
            build_stdout += f"[DEBUG] Profil C2 détecté: {profile.get('name', 'unknown')}\n"
            
            if profile.get("name") != "http":
                build_stderr += f"Hermes ne supporte que le profil C2 HTTP. Profil détecté: {profile.get('name', 'unknown')}\n"
                return BuildResponse(
                    status=BuildStatus.Error,
                    build_stdout=build_stdout,
                    build_stderr=build_stderr,
                )

            params = c2.get_parameters_dict()
            
            # Extraire callback_host
            try:
                callback_host_raw = params.get("callback_host")
                if isinstance(callback_host_raw, dict):
                    callback_host = callback_host_raw.get("value", "")
                else:
                    callback_host = str(callback_host_raw) if callback_host_raw else ""
            except Exception as e:
                build_stderr += f"Warning: Erreur lors de l'extraction de callback_host: {e}\n"
                callback_host = ""
            
            # Check for dangerous default values
            if not callback_host or callback_host in ["https://domain.com", "http://domain.com", "domain.com"]:
                build_stderr += f"ATTENTION: callback_host est défini sur '{callback_host}' (valeur par défaut).\n"
                build_stderr += "Veuillez configurer le profil HTTP avec votre adresse/IP réelle.\n"
                build_stderr += "Le build continuera mais l'agent ne pourra pas se connecter.\n\n"
            
            callback_host = callback_host or "http://127.0.0.1"
            
            # Extraire callback_port
            callback_port = 443
            try:
                if "callback_port" in params:
                    v = params["callback_port"]
                    if isinstance(v, dict):
                        callback_port = int(v.get("value", 443))
                    else:
                        callback_port = int(v) if v else 443
                elif "port" in params:
                    v = params["port"]
                    if isinstance(v, dict):
                        callback_port = int(v.get("value", 443))
                    else:
                        callback_port = int(v) if v else 443
            except (ValueError, TypeError) as e:
                build_stderr += f"Warning: Erreur lors de l'extraction du port, utilisation de 443 par défaut: {e}\n"
                callback_port = 443

            # Extract post_uri
            try:
                post_uri_raw = params.get("post_uri")
                if isinstance(post_uri_raw, dict):
                    post_uri = post_uri_raw.get("value", "/api/v1.4/agent_message")
                else:
                    post_uri = str(post_uri_raw) if post_uri_raw else "/api/v1.4/agent_message"
                # S'assurer que post_uri commence par /
                if post_uri and not post_uri.startswith("/"):
                    post_uri = "/" + post_uri
            except Exception as e:
                build_stderr += f"Warning: Erreur lors de l'extraction de post_uri: {e}\n"
                post_uri = "/api/v1.4/agent_message"

            # Extraire headers
            headers_raw = params.get("headers")
            headers = {}
            try:
                if isinstance(headers_raw, dict):
                    if "value" in headers_raw:
                        # headers can be a dict with "value" containing a dict or JSON string
                        val = headers_raw.get("value")
                        if isinstance(val, dict):
                            headers = val
                        elif isinstance(val, str):
                            try:
                                headers = json.loads(val)
                            except json.JSONDecodeError:
                                headers = {}
                    else:
                        # headers est directement un dict
                        headers = headers_raw
                elif isinstance(headers_raw, str):
                    # headers est une string JSON
                    try:
                        headers = json.loads(headers_raw)
                    except json.JSONDecodeError:
                        headers = {}
            except Exception as e:
                build_stderr += f"Warning: Erreur lors de l'extraction des headers: {e}\n"
                headers = {}
            
            headers_json = json.dumps(headers)

            # Extraire interval
            try:
                interval_raw = params.get("callback_interval")
                if isinstance(interval_raw, dict):
                    interval = int(interval_raw.get("value", 10))
                else:
                    interval = int(interval_raw or 10)
            except (ValueError, TypeError):
                interval = 10
            
            # Extract jitter
            try:
                jitter_raw = params.get("callback_jitter")
                if isinstance(jitter_raw, dict):
                    jitter = int(jitter_raw.get("value", 0))
                else:
                    jitter = int(jitter_raw or 0)
            except (ValueError, TypeError):
                jitter = 0
            
            # Extract killdate
            killdate = ""
            try:
                if "killdate" in params:
                    v = params["killdate"]
                    if isinstance(v, dict):
                        killdate = v.get("value") or ""
                    else:
                        killdate = str(v) if v else ""
            except Exception:
                killdate = ""

            # Build base_url
            try:
                if "://" not in callback_host:
                    callback_host = "https://" + callback_host
                # Clean callback_host (remove port if already present)
                if ":" in callback_host.split("://")[1]:
                    # Port already present in callback_host
                    base_url = callback_host.rstrip("/")
                else:
                    base_url = f"{callback_host.rstrip('/')}:{callback_port}"
                if not base_url.endswith("/"):
                    base_url += "/"
            except Exception as e:
                build_stderr += f"Warning: Erreur lors de la construction de base_url: {e}\n"
                base_url = "http://127.0.0.1:80/"

            build_stdout += "[+] Step 1: Gathering files...\n"
            agent_src = self.agent_code_path / "agent.py"
            if not agent_src.exists():
                build_stderr += f"File not found: {agent_src}\n"
                return BuildResponse(
                    status=BuildStatus.Error,
                    build_stdout=build_stdout,
                    build_stderr=build_stderr,
                )

            content = agent_src.read_text(encoding="utf-8")
            build_stdout += "[+] Step 2: Injecting config...\n"

            # Replace placeholders - replace value between quotes
            import re
            # UUID, BASE_URL, POST_URI, HEADERS_JSON, KILLDATE are JSON strings
            content = re.sub(r'(CONFIG_UUID\s*=\s*)"[^"]*"', rf'\1{json.dumps(self.uuid)}', content, count=1)
            content = re.sub(r'(CONFIG_BASE_URL\s*=\s*)"[^"]*"', rf'\1{json.dumps(base_url)}', content, count=1)
            content = re.sub(r'(CONFIG_POST_URI\s*=\s*)"[^"]*"', rf'\1{json.dumps(post_uri)}', content, count=1)
            # headers_json is already a JSON string, inject it directly
            content = re.sub(r'(CONFIG_HEADERS_JSON\s*=\s*)"[^"]*"', rf'\1{json.dumps(headers_json)}', content, count=1)
            # CONFIG_INTERVAL and CONFIG_JITTER must remain strings (converted to int in agent)
            content = re.sub(r'(CONFIG_INTERVAL\s*=\s*)"[^"]*"', rf'\1"{interval}"', content, count=1)
            content = re.sub(r'(CONFIG_JITTER\s*=\s*)"[^"]*"', rf'\1"{jitter}"', content, count=1)
            content = re.sub(r'(CONFIG_KILLDATE\s*=\s*)"[^"]*"', rf'\1{json.dumps(killdate)}', content, count=1)

            build_stdout += "[+] Étape 3: Finalisation...\n"
            payload_bytes = content.encode("utf-8")
            output_type = self.get_parameter("output_type") or "python"

            if output_type == "zip":
                import zipfile
                import io
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("agent.py", content)
                    req = (self.agent_code_path / "requirements.txt").read_text(encoding="utf-8")
                    zf.writestr("requirements.txt", req)
                zip_bytes = buf.getvalue()
                encoded_payload = base64.b64encode(zip_bytes).decode("ascii")
                build_stdout += f"[+] ZIP payload generated ({len(zip_bytes)} bytes).\n"
            else:
                encoded_payload = base64.b64encode(payload_bytes).decode("ascii")
                build_stdout += f"[+] Python payload generated ({len(payload_bytes)} bytes).\n"

            build_stdout += "[+] Hermes build completed successfully.\n"
            return BuildResponse(
                status=BuildStatus.Success,
                payload=encoded_payload,
                build_message="Hermes build successful",
                build_stdout=build_stdout,
                build_stderr=build_stderr,
            )

        except Exception as e:
            import traceback
            build_stderr += f"Erreur: {str(e)}\n"
            build_stderr += f"Traceback: {traceback.format_exc()}\n"
            build_stderr += f"Type de l'erreur: {type(e).__name__}\n"
            return BuildResponse(
                status=BuildStatus.Error,
                build_stdout=build_stdout,
                build_stderr=build_stderr,
            )
