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
    c2_profiles = ["http", "notion"]
    build_parameters = [
        BuildParameter(
            name="output_type",
            parameter_type=BuildParameterType.ChooseOne,
            description="Output type",
            choices=["python", "zip"],
            default_value="python",
            required=False,
        ),
    ]
    agent_path = Path("agent_functions")
    agent_code_path = Path("agent_code")
    # Icon is in agent_functions directory (like Apollo)
    agent_icon_path = agent_path / "hermes.svg"
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
            build_stdout += f"[DEBUG] C2 profile detected: {profile.get('name', 'unknown')}\n"
            
            profile_name = profile.get("name", "")
            if profile_name not in ("http", "notion"):
                build_stderr += f"Hermes supports http and notion C2 profiles. Detected: {profile_name}\n"
                return BuildResponse(
                    status=BuildStatus.Error,
                    build_stdout=build_stdout,
                    build_stderr=build_stderr,
                )

            params = c2.get_parameters_dict()

            # --- Common parameters (interval, jitter, killdate, crypto) ---
            def _extract(p, key, default):
                v = p.get(key, default)
                return v.get("value", default) if isinstance(v, dict) else (v if v is not None else default)

            try:
                interval = int(_extract(params, "callback_interval", 10))
            except (ValueError, TypeError):
                interval = 10

            try:
                jitter = int(_extract(params, "callback_jitter", 0))
            except (ValueError, TypeError):
                jitter = 0

            killdate = str(_extract(params, "killdate", "") or "")

            eec_raw = _extract(params, "encrypted_exchange_check", True)
            if isinstance(eec_raw, bool):
                use_psk = not eec_raw
            else:
                use_psk = str(eec_raw).lower() in ("false", "0", "f", "no")

            # Always extract AESPSK: needed for staging encryption in EKE mode too.
            # Per Mythic docs, staging_rsa messages are encrypted with the AESPSK.
            aes_psk_b64 = ""
            try:
                raw = params.get("AESPSK")
                if isinstance(raw, dict):
                    aes_psk_b64 = (
                        str(raw.get("enc_key") or "").strip()
                        or str((raw.get("value") or {}).get("enc_key") or "").strip()
                        or str(raw.get("value") or "").strip()
                    )
                elif isinstance(raw, str):
                    aes_psk_b64 = raw.strip()
            except Exception as e:
                build_stderr += f"AESPSK extraction error: {e}\n"
            if use_psk and not aes_psk_b64:
                build_stderr += "AESPSK requested but key is missing or empty.\n"

            import re

            if profile_name == "http":
                # --- HTTP profile ---
                callback_host = str(_extract(params, "callback_host", "") or "")
                if not callback_host or callback_host in ("https://domain.com", "http://domain.com", "domain.com"):
                    build_stderr += f"WARNING: callback_host='{callback_host}' looks like a default. Agent may not connect.\n"
                callback_host = callback_host or "http://127.0.0.1"

                try:
                    callback_port = int(_extract(params, "callback_port", _extract(params, "port", 443)))
                except (ValueError, TypeError):
                    callback_port = 443

                post_uri = str(_extract(params, "post_uri", "/api/v1.4/agent_message") or "/api/v1.4/agent_message")
                if not post_uri.startswith("/"):
                    post_uri = "/" + post_uri

                headers_raw = params.get("headers", {})
                headers = {}
                try:
                    if isinstance(headers_raw, dict):
                        val = headers_raw.get("value", headers_raw)
                        headers = json.loads(val) if isinstance(val, str) else (val if isinstance(val, dict) else {})
                    elif isinstance(headers_raw, str):
                        headers = json.loads(headers_raw)
                except Exception:
                    headers = {}
                headers_json = json.dumps(headers)

                try:
                    if "://" not in callback_host:
                        callback_host = "https://" + callback_host
                    host_part = callback_host.split("://")[1]
                    base_url = callback_host.rstrip("/") if ":" in host_part else f"{callback_host.rstrip('/')}:{callback_port}"
                    if not base_url.endswith("/"):
                        base_url += "/"
                except Exception as e:
                    build_stderr += f"Warning: building base_url: {e}\n"
                    base_url = "http://127.0.0.1:80/"

                build_stdout += "[+] Step 1: Gathering files...\n"
                agent_src = self.agent_code_path / "agent.http" / "agent.py"
                req_path = self.agent_code_path / "agent.http" / "requirements.txt"
                if not agent_src.exists():
                    build_stderr += f"File not found: {agent_src}\n"
                    return BuildResponse(status=BuildStatus.Error, build_stdout=build_stdout, build_stderr=build_stderr)

                content = agent_src.read_text(encoding="utf-8")
                build_stdout += "[+] Step 2: Injecting config (http)...\n"

                content = re.sub(r'(CONFIG_UUID\s*=\s*)"[^"]*"', rf'\1{json.dumps(self.uuid)}', content, count=1)
                content = re.sub(r'(CONFIG_BASE_URL\s*=\s*)"[^"]*"', rf'\1{json.dumps(base_url)}', content, count=1)
                content = re.sub(r'(CONFIG_POST_URI\s*=\s*)"[^"]*"', rf'\1{json.dumps(post_uri)}', content, count=1)
                content = re.sub(r'(CONFIG_HEADERS_JSON\s*=\s*)"[^"]*"', rf'\1{json.dumps(headers_json)}', content, count=1)
                content = re.sub(r'(CONFIG_INTERVAL\s*=\s*)"[^"]*"', rf'\1"{interval}"', content, count=1)
                content = re.sub(r'(CONFIG_JITTER\s*=\s*)"[^"]*"', rf'\1"{jitter}"', content, count=1)
                content = re.sub(r'(CONFIG_KILLDATE\s*=\s*)"[^"]*"', rf'\1{json.dumps(killdate)}', content, count=1)
                content = re.sub(r'(CONFIG_USE_PSK\s*=\s*)"[^"]*"', rf'\1"{str(use_psk).lower()}"', content, count=1)
                content = re.sub(r'(CONFIG_AESPSK\s*=\s*)"[^"]*"', rf'\1{json.dumps(aes_psk_b64)}', content, count=1)

            else:
                # --- Notion profile ---
                notion_token = str(_extract(params, "integration_token", "") or "")
                notion_db_id = str(_extract(params, "database_id", "") or "")

                if not notion_token:
                    build_stderr += "ERROR: integration_token is required for the notion C2 profile.\n"
                    return BuildResponse(status=BuildStatus.Error, build_stdout=build_stdout, build_stderr=build_stderr)
                if not notion_db_id:
                    build_stderr += "ERROR: database_id is required for the notion C2 profile.\n"
                    return BuildResponse(status=BuildStatus.Error, build_stdout=build_stdout, build_stderr=build_stderr)

                build_stdout += "[+] Step 1: Gathering files...\n"
                agent_src = self.agent_code_path / "agent.notion" / "agent_notion.py"
                req_path = self.agent_code_path / "agent.notion" / "requirements.txt"
                if not agent_src.exists():
                    build_stderr += f"File not found: {agent_src}\n"
                    return BuildResponse(status=BuildStatus.Error, build_stdout=build_stdout, build_stderr=build_stderr)

                content = agent_src.read_text(encoding="utf-8")
                build_stdout += "[+] Step 2: Injecting config (notion)...\n"

                content = re.sub(r'(CONFIG_UUID\s*=\s*)"[^"]*"', rf'\1{json.dumps(self.uuid)}', content, count=1)
                content = re.sub(r'(CONFIG_NOTION_TOKEN\s*=\s*)"[^"]*"', rf'\1{json.dumps(notion_token)}', content, count=1)
                content = re.sub(r'(CONFIG_NOTION_DB_ID\s*=\s*)"[^"]*"', rf'\1{json.dumps(notion_db_id)}', content, count=1)
                content = re.sub(r'(CONFIG_INTERVAL\s*=\s*)"[^"]*"', rf'\1"{interval}"', content, count=1)
                content = re.sub(r'(CONFIG_JITTER\s*=\s*)"[^"]*"', rf'\1"{jitter}"', content, count=1)
                content = re.sub(r'(CONFIG_KILLDATE\s*=\s*)"[^"]*"', rf'\1{json.dumps(killdate)}', content, count=1)
                content = re.sub(r'(CONFIG_USE_PSK\s*=\s*)"[^"]*"', rf'\1"{str(use_psk).lower()}"', content, count=1)
                content = re.sub(r'(CONFIG_AESPSK\s*=\s*)"[^"]*"', rf'\1{json.dumps(aes_psk_b64)}', content, count=1)

            build_stdout += "[+] Step 3: Finalizing...\n"
            payload_bytes = content.encode("utf-8")
            output_type = self.get_parameter("output_type") or "python"

            if output_type == "zip":
                import zipfile
                import io
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr("agent.py", content)
                    req = req_path.read_text(encoding="utf-8")
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
            build_stderr += f"Error: {str(e)}\n"
            build_stderr += f"Traceback: {traceback.format_exc()}\n"
            build_stderr += f"Error type: {type(e).__name__}\n"
            return BuildResponse(
                status=BuildStatus.Error,
                build_stdout=build_stdout,
                build_stderr=build_stderr,
            )
