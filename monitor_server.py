#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import re
import secrets
import shlex
import subprocess
import sys
import tempfile
import threading
import time
import traceback
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse, parse_qs


_IS_MACOS = sys.platform == "darwin"
if _IS_MACOS:
    try:
        import psutil as _psutil
    except ImportError:
        subprocess.run([sys.executable, "-m", "pip", "install", "psutil", "-q", "--user"], check=True)
        import psutil as _psutil


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"


DEFAULT_CONFIG: dict[str, Any] = {
    "refresh_interval_sec": 10,
    "session_scan_limit": 120,
    "aliases_file": str(BASE_DIR / "session_aliases.json"),
    "session_bindings_file": str(BASE_DIR / "session_bindings.json"),
    "credentials_file": str(BASE_DIR / "credentials.enc.json"),
    "send_mode": "stdin",
    "probe_timeout_sec": 20,
    "probe_message_template": "请只回复：{token}",
    "managed_hosts": [],
    "dashboard": {
        "agent_types": ["codex", "claude", "droid"],
        "hide_empty_tools": True,
    },
    "status": {
        "busy_cpu_threshold": 20.0,
        "active_heartbeat_sec": 120,
        "stale_heartbeat_sec": 900,
        "needs_input_patterns": [
            r"\?$",
            r"please provide",
            r"if you.d like",
            r"can you",
            r"need you to",
            r"would you like",
            r"do you want",
            r"shall i",
            r"should i",
            r"which (option|approach|version|one)",
            r"let me know",
            r"我需要",
            r"请提供",
            r"如果你愿意",
            r"要的话",
            r"您是否",
            r"是否需要",
            r"需要我",
            r"您想",
            r"你想",
            r"可以告诉我",
            r"请问",
            r"请确认",
            r"请选择",
        ],
    },
    "paths": {
        "codex_sessions": "~/.codex/sessions",
        "claude_projects": "~/.claude/projects",
        "claude_todos": "~/.claude/todos",
        "claude_tasks": "~/.claude/tasks",
    },
    "hosts": [
        {
            "name": "local",
            "mode": "local",
        }
    ],
}


def shell_quote(value: str) -> str:
    return shlex.quote(value)


def read_json_file(path: str | Path, default: Any) -> Any:
    try:
        p = Path(path)
        if not p.exists():
            return default
        return json.loads(p.read_text(encoding="utf-8"))
    except Exception:
        return default


def write_json_file(path: str | Path, data: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def resolve_relative_path(base_dir: Path, value: str | None) -> str | None:
    if not value:
        return None
    path = Path(os.path.expanduser(value))
    if not path.is_absolute():
        path = base_dir / path
    return str(path)


def sanitize_config(config: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in config.items() if not str(k).startswith("_")}


def write_config(config: dict[str, Any]) -> None:
    path = Path(config["_config_path"])
    write_json_file(path, sanitize_config(config))


def openssl_crypt(payload: str, password: str, *, decrypt: bool, iterations: int = 390000) -> str:
    if not password:
        raise ValueError("Master password cannot be empty")
    cmd = [
        "openssl",
        "enc",
        "-aes-256-cbc",
        "-pbkdf2",
        "-iter",
        str(iterations),
        "-a",
        "-A",
        "-pass",
        "env:AGENT_FOREMAN_MASTER_PASSWORD",
    ]
    if decrypt:
        cmd.append("-d")
    else:
        cmd.append("-salt")
    env = os.environ.copy()
    env["AGENT_FOREMAN_MASTER_PASSWORD"] = password
    proc = subprocess.run(
        cmd,
        input=payload,
        capture_output=True,
        text=True,
        timeout=10,
        env=env,
    )
    if proc.returncode != 0:
        message = proc.stderr.strip() or proc.stdout.strip() or "openssl failed"
        raise ValueError(message) if decrypt else RuntimeError(message)
    return proc.stdout.strip()


class CredentialVault:
    def __init__(self, path: str | Path, iterations: int = 390000):
        self.path = Path(path)
        self.iterations = iterations
        self._master_password: str | None = None
        self._data: dict[str, Any] = {"hosts": {}}

    @property
    def is_unlocked(self) -> bool:
        return self._master_password is not None

    def exists(self) -> bool:
        return self.path.exists()

    def create(self, master_password: str) -> None:
        self._master_password = master_password
        self._data = {"hosts": {}}
        self._persist()

    def unlock(self, master_password: str) -> None:
        if not self.path.exists():
            raise FileNotFoundError(self.path)
        envelope = read_json_file(self.path, None)
        if not isinstance(envelope, dict) or "payload_b64" not in envelope:
            raise ValueError("Credential vault is invalid")
        plaintext = openssl_crypt(
            str(envelope["payload_b64"]),
            master_password,
            decrypt=True,
            iterations=int(envelope.get("iterations", self.iterations)),
        )
        data = safe_json_loads(plaintext)
        if not isinstance(data, dict):
            raise ValueError("Credential vault payload is invalid")
        if "hosts" not in data or not isinstance(data["hosts"], dict):
            data["hosts"] = {}
        self.iterations = int(envelope.get("iterations", self.iterations))
        self._master_password = master_password
        self._data = data

    def get(self, host_id: str) -> dict[str, str] | None:
        value = self._data.get("hosts", {}).get(host_id)
        if not isinstance(value, dict):
            return None
        return {"username": str(value.get("username", "")), "password": str(value.get("password", ""))}

    def upsert(self, host_id: str, username: str, password: str) -> None:
        if not self.is_unlocked:
            raise ValueError("Credential vault is locked")
        self._data.setdefault("hosts", {})[host_id] = {
            "username": username,
            "password": password,
        }
        self._persist()

    def delete(self, host_id: str) -> None:
        if not self.is_unlocked:
            raise ValueError("Credential vault is locked")
        self._data.setdefault("hosts", {}).pop(host_id, None)
        self._persist()

    def _persist(self) -> None:
        if not self._master_password:
            raise ValueError("Credential vault is locked")
        plaintext = json.dumps(self._data, ensure_ascii=False, indent=2)
        ciphertext = openssl_crypt(
            plaintext,
            self._master_password,
            decrypt=False,
            iterations=self.iterations,
        )
        write_json_file(
            self.path,
            {
                "version": 1,
                "cipher": "aes-256-cbc",
                "kdf": "pbkdf2",
                "iterations": self.iterations,
                "payload_b64": ciphertext,
            },
        )


class ManagedHostStore:
    def __init__(self, config: dict[str, Any], vault: CredentialVault):
        self.config = config
        self.vault = vault
        self.config.setdefault("managed_hosts", [])

    def get_host(self, host_id: str) -> dict[str, Any] | None:
        for host in self.config.get("managed_hosts", []):
            if host.get("id") == host_id:
                return host
        return None

    def list_hosts(self, snapshot: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        errors: dict[str, str] = {}
        if snapshot:
            for host in snapshot.get("hosts", []):
                if host.get("error") and host.get("host_id"):
                    errors[str(host["host_id"])] = str(host["error"])
        items = []
        for host in self.config.get("managed_hosts", []):
            safe = dict(host)
            creds = self.vault.get(str(host["id"])) or {}
            safe["username"] = creds.get("username", "")
            safe["has_password"] = bool(creds.get("password"))
            safe["last_error"] = errors.get(str(host["id"]))
            items.append(safe)
        return items

    def build_draft(self, payload: dict[str, Any]) -> dict[str, Any]:
        host_id = str(payload.get("id", "")).strip()
        existing = self.get_host(host_id) if host_id else None
        existing_creds = (self.vault.get(host_id) if self.vault else None) if host_id else None
        username = str(payload.get("username", "")).strip() or (existing_creds or {}).get("username", "")
        password = str(payload.get("password", ""))
        if not password:
            password = (existing_creds or {}).get("password", "")
        mode = str(payload.get("mode", "ssh_password"))
        draft = {
            "id": host_id or (existing or {}).get("id"),
            "name": str(payload.get("name", "")).strip() or str((existing or {}).get("name", "")).strip(),
            "ssh_target": str(payload.get("ssh_target", "")).strip() or str((existing or {}).get("ssh_target", "")).strip(),
            "port": payload.get("port", (existing or {}).get("port", 22)),
            "send_mode": str(payload.get("send_mode", "")).strip() or str((existing or {}).get("send_mode", "stdin")).strip() or "stdin",
            "enabled": bool(payload.get("enabled", (existing or {}).get("enabled", True))),
            "username": username,
            "password": password,
            "mode": mode,
        }
        self._validate_payload(draft, existing=existing)
        return draft

    def save_host(self, payload: dict[str, Any]) -> dict[str, Any]:
        existing = self.get_host(str(payload.get("id", "")).strip()) if payload.get("id") else None
        draft = self.build_draft(payload)
        host_id = draft["id"] or f"host-{secrets.token_hex(4)}"
        mode = payload.get("mode", "ssh_password")
        if mode not in ("ssh", "ssh_password"):
            mode = "ssh_password"
        record = {
            "id": host_id,
            "name": draft["name"],
            "mode": mode,
            "ssh_target": draft["ssh_target"],
            "port": int(draft["port"]),
            "enabled": bool(draft["enabled"]),
            "send_mode": draft["send_mode"],
        }
        managed_hosts = [host for host in self.config.get("managed_hosts", []) if host.get("id") != host_id]
        managed_hosts.append(record)
        managed_hosts.sort(key=lambda item: str(item.get("name", "")))
        self.config["managed_hosts"] = managed_hosts
        write_config(self.config)
        if mode == "ssh_password" and self.vault is not None:
            self.vault.upsert(host_id, draft["username"], draft["password"])
        return dict(record, username=draft["username"], has_password=(mode == "ssh_password"))

    def delete_host(self, host_id: str) -> None:
        self.config["managed_hosts"] = [host for host in self.config.get("managed_hosts", []) if host.get("id") != host_id]
        write_config(self.config)
        if self.vault is not None:
            self.vault.delete(host_id)

    def toggle_host(self, host_id: str, enabled: bool) -> dict[str, Any]:
        host = self.get_host(host_id)
        if not host:
            raise ValueError("Host not found")
        host["enabled"] = bool(enabled)
        write_config(self.config)
        return host

    def runtime_hosts(self) -> list[dict[str, Any]]:
        result = []
        for host in self.config.get("managed_hosts", []):
            if not host.get("enabled", True):
                continue
            creds = (self.vault.get(host["id"]) if self.vault else None) or {}
            entry = {
                "id": host["id"],
                "name": host["name"],
                "mode": host.get("mode", "ssh_password"),
                "ssh_target": host["ssh_target"],
                "port": host.get("port", 22),
                "send_mode": host.get("send_mode", "stdin"),
            }
            username = host.get("username") or creds.get("username", "")
            if username:
                entry["username"] = username
            result.append(entry)
        return result

    def _validate_payload(self, payload: dict[str, Any], existing: dict[str, Any] | None = None) -> None:
        if not payload.get("name"):
            raise ValueError("Host name is required")
        if not payload.get("ssh_target"):
            raise ValueError("Host or IP is required")
        if not payload.get("username"):
            raise ValueError("Username is required")
        password = str(payload.get("password", ""))
        mode = str(payload.get("mode", "ssh_password"))
        if mode == "ssh_password" and not password and not existing:
            raise ValueError("Password is required for a new host")
        try:
            port = int(payload.get("port", 22))
        except Exception as exc:
            raise ValueError("Port must be an integer") from exc
        if port < 1 or port > 65535:
            raise ValueError("Port must be between 1 and 65535")
        if payload.get("send_mode", "stdin") not in {"stdin", "cmux"}:
            raise ValueError("Unsupported send_mode")


def configured_hosts(config: dict[str, Any], vault: CredentialVault | None = None) -> list[dict[str, Any]]:
    hosts = list(config.get("hosts", []))
    store = ManagedHostStore(config, vault)
    for h in store.runtime_hosts():
        # ssh_password hosts require vault; skip them if vault is unavailable
        if h.get("mode") == "ssh_password" and vault is None:
            continue
        hosts.append(h)
    return hosts


def host_identity(host_cfg: dict[str, Any]) -> str:
    return str(host_cfg.get("id") or host_cfg.get("name"))


def build_password_ssh_command(host_cfg: dict[str, Any], username: str, remote_command: str) -> list[str]:
    cmd = [
        "setsid",
        "ssh",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "NumberOfPasswordPrompts=1",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "ConnectTimeout=8",
    ]
    if host_cfg.get("port"):
        cmd += ["-p", str(host_cfg["port"])]
    cmd += [f"{username}@{host_cfg['ssh_target']}", remote_command]
    return cmd


def run_password_ssh_command(
    host_cfg: dict[str, Any],
    creds: dict[str, str],
    remote_command: str,
    *,
    stdin_data: str | None = None,
    timeout: int = 25,
) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="foreman-askpass-") as tmpdir:
        askpass = Path(tmpdir) / "askpass.sh"
        askpass.write_text("#!/bin/sh\nprintf '%s' \"$AGENT_FOREMAN_ASKPASS\"\n", encoding="utf-8")
        askpass.chmod(0o700)
        env = os.environ.copy()
        env["DISPLAY"] = ":0"
        env["SSH_ASKPASS"] = str(askpass)
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env["AGENT_FOREMAN_ASKPASS"] = creds["password"]
        proc = subprocess.run(
            build_password_ssh_command(host_cfg, creds["username"], remote_command),
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
        )
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


def run_ssh_probe_password(host_cfg: dict[str, Any], creds: dict[str, str], config: dict[str, Any]) -> dict[str, Any]:
    source = Path(__file__).read_text(encoding="utf-8")
    payload = base64.b64encode(json.dumps({"config": config, "host": host_cfg}).encode()).decode()
    result = run_password_ssh_command(
        host_cfg,
        creds,
        f"python3 - --probe {payload}",
        stdin_data=source,
    )
    if result["returncode"] != 0:
        raise RuntimeError(result["stderr"].strip() or result["stdout"].strip() or f"ssh exit {result['returncode']}")
    return json.loads(result["stdout"])


def run_remote_shell_password(host_cfg: dict[str, Any], creds: dict[str, str], template: str, agent: dict[str, Any], message: str) -> dict[str, Any]:
    exports = {
        "AGENT_ID": str(agent.get("id", "")),
        "AGENT_TYPE": str(agent.get("agent_type", "")),
        "AGENT_PID": str(agent.get("pid", "")),
        "AGENT_SESSION_ID": str(agent.get("session_id", "")),
        "AGENT_CWD": str(agent.get("cwd", "")),
        "AGENT_PROJECT": str(agent.get("project", "")),
        "AGENT_BRANCH": str(agent.get("branch", "")),
        "AGENT_MESSAGE": message,
        "AGENT_MESSAGE_B64": base64.b64encode(message.encode("utf-8")).decode(),
    }
    export_str = " ".join(f"{k}={shell_quote(v)}" for k, v in exports.items())
    return run_password_ssh_command(
        host_cfg,
        creds,
        f"{export_str} /bin/bash -lc {shell_quote(template)}",
        timeout=20,
    )


def send_via_stdin_remote_password(host_cfg: dict[str, Any], creds: dict[str, str], agent: dict[str, Any], message: str) -> dict[str, Any]:
    pid = int(agent["pid"])
    payload_b64 = base64.b64encode((message + "\r").encode()).decode()
    py_script = (
        "import base64,os,sys,subprocess,traceback\n"
        f"payload=base64.b64decode('{payload_b64}')\n"
        f"pid={pid}\n"
        "msg=payload.rstrip(b'\\x0d').decode()\n"
        "errors=[]\n"
        # 1. Try tmux - find pane by scanning all tmux panes for matching pid
        "try:\n"
        "  pane=None\n"
        "  # Try psutil first\n"
        "  try:\n"
        "    import psutil\n"
        "    cur=pid\n"
        "    for _ in range(6):\n"
        "      try:\n"
        "        e=psutil.Process(cur).environ()\n"
        "        if 'TMUX_PANE' in e:pane=e['TMUX_PANE'];break\n"
        "        cur=psutil.Process(cur).ppid()\n"
        "      except:break\n"
        "  except:pass\n"
        "  # Fallback: use ps to build ancestor set and match against tmux pane pids\n"
        "  if not pane:\n"
        "    try:\n"
        "      _tmux=__import__('shutil').which('tmux') or '/usr/local/bin/tmux'\n"
        "      panes_out=subprocess.check_output([_tmux,'list-panes','-a','-F','#{pane_id} #{pane_pid}'],timeout=5).decode()\n"
        "      # build ancestor pids via ps\n"
        "      ancestors={pid}\n"
        "      cur=pid\n"
        "      for _ in range(10):\n"
        "        try:\n"
        "          ppid=int(subprocess.check_output(['ps','-o','ppid=','-p',str(cur)],timeout=3).decode().strip())\n"
        "          if ppid<=1:break\n"
        "          ancestors.add(ppid);cur=ppid\n"
        "        except:break\n"
        "      for line in panes_out.strip().split('\\n'):\n"
        "        parts=line.split()\n"
        "        if len(parts)==2:\n"
        "          try:\n"
        "            if int(parts[1]) in ancestors:pane=parts[0];break\n"
        "          except:pass\n"
        "    except:pass\n"
        "  if pane:\n"
        "    _tmux=__import__('shutil').which('tmux') or '/usr/local/bin/tmux'\n"
        "    r=subprocess.run([_tmux,'send-keys','-t',pane,'-l',msg+'\\r'],capture_output=True,timeout=10)\n"
        "    if r.returncode==0:\n"
        "      sys.stdout.write('ok:tmux:'+pane+'\\n');sys.stdout.flush();os._exit(0)\n"
        "    else:errors.append('tmux:'+r.stderr.decode()[:100])\n"
        "  else:errors.append('tmux:no pane found')\n"
        "except Exception as e:errors.append('tmux:'+str(e))\n"
        # 2. Linux TIOCSTI (direct - works if same user and kernel allows)
        "try:\n"
        "  import fcntl\n"
        "  slave=os.readlink(f'/proc/{pid}/fd/0')\n"
        "  f=open(slave,'rb',buffering=0)\n"
        "  for b in payload:fcntl.ioctl(f,0x5412,bytes([b]))\n"
        "  f.close();sys.stdout.write('ok:tiocsti\\n');sys.stdout.flush();os._exit(0)\n"
        "except Exception as e:errors.append('tiocsti:'+str(e))\n"
        # 3. Linux ptrace TIOCSTI (inject ioctl via ptrace - works when direct TIOCSTI is blocked)
        "try:\n"
        "  import ctypes,ctypes.util,struct\n"
        "  libc=ctypes.CDLL(ctypes.util.find_library('c'),use_errno=True)\n"
        "  libc.ptrace.restype=ctypes.c_long\n"
        "  libc.ptrace.argtypes=[ctypes.c_long]*2+[ctypes.c_void_p]*2\n"
        "  PA,PD,PGR,PSR,PPD,PSS=16,17,12,13,5,9\n"
        "  TIOCSTI,SYS_ioctl=0x5412,16\n"
        "  class R(ctypes.Structure):\n"
        "    _fields_=[(n,ctypes.c_ulonglong) for n in ['r15','r14','r13','r12','rbp','rbx','r11','r10','r9','r8','rax','rcx','rdx','rsi','rdi','orig_rax','rip','cs','eflags','rsp','ss','fs_base','gs_base','ds','es','fs','gs']]\n"
        "  sa=None\n"
        "  for line in open(f'/proc/{pid}/maps'):\n"
        "    if 'r-xp' not in line:continue\n"
        "    p=line.split();s,e=[int(x,16) for x in p[0].split('-')];off=int(p[2],16);path=p[5] if len(p)>5 else ''\n"
        "    if not path or path.startswith('['):continue\n"
        "    try:\n"
        "      with open(path,'rb') as bf:bf.seek(off);d=bf.read(e-s)\n"
        "      i=d.find(b'\\x0f\\x05')\n"
        "      if i>=0:sa=s+i;break\n"
        "    except:continue\n"
        "  if not sa:raise RuntimeError('no syscall gadget')\n"
        "  if libc.ptrace(PA,pid,None,None)<0:raise OSError('ptrace attach failed')\n"
        "  os.waitpid(pid,0)\n"
        "  regs=R();libc.ptrace(PGR,pid,None,ctypes.byref(regs))\n"
        "  saved={f:getattr(regs,f) for f,_ in R._fields_};scratch=regs.rsp-256\n"
        "  try:\n"
        "    for byte in payload:\n"
        "      libc.ptrace(PPD,pid,ctypes.c_void_p(scratch),ctypes.c_void_p(int(byte)))\n"
        "      regs.rip=sa;regs.rax=SYS_ioctl;regs.rdi=0;regs.rsi=TIOCSTI;regs.rdx=scratch\n"
        "      libc.ptrace(PSR,pid,None,ctypes.byref(regs));libc.ptrace(PSS,pid,None,None);os.waitpid(pid,0)\n"
        "  finally:\n"
        "    for f,_ in R._fields_:setattr(regs,f,saved[f])\n"
        "    libc.ptrace(PSR,pid,None,ctypes.byref(regs));libc.ptrace(PD,pid,None,None)\n"
        "  sys.stdout.write('ok:ptrace\\n');sys.stdout.flush();os._exit(0)\n"
        "except Exception as e:errors.append('ptrace:'+str(e))\n"
        "sys.stdout.write('fail:'+'|'.join(errors)+'\\n');sys.stdout.flush();os._exit(1)\n"
    )
    return run_password_ssh_command(host_cfg, creds, f"python3 -c {shell_quote(py_script)}", timeout=20)


def test_managed_host_connection(draft: dict[str, Any], config: dict[str, Any] | None = None) -> dict[str, Any]:
    mode = str(draft.get("mode", "ssh_password"))
    if mode not in ("ssh", "ssh_password"):
        mode = "ssh_password"
    host_cfg = {
        "id": str(draft.get("id") or "test-host"),
        "name": str(draft.get("name") or draft.get("ssh_target") or "test-host"),
        "mode": mode,
        "ssh_target": str(draft.get("ssh_target", "")),
        "port": int(draft.get("port", 22)),
        "send_mode": str(draft.get("send_mode", "stdin") or "stdin"),
    }
    probe_config = json.loads(json.dumps(DEFAULT_CONFIG))
    if config:
        probe_config.update({k: v for k, v in config.items() if not str(k).startswith("_") and k not in {"status", "paths", "hosts", "managed_hosts"}})
        probe_config["status"].update(config.get("status", {}))
        probe_config["paths"].update(config.get("paths", {}))
    try:
        if mode == "ssh_password":
            creds = {
                "username": str(draft.get("username", "")),
                "password": str(draft.get("password", "")),
            }
            snapshot = run_ssh_probe_password(host_cfg, creds, probe_config)
        else:
            snapshot = run_ssh_probe(host_cfg, probe_config)
        return {
            "ok": True,
            "agent_count": len(snapshot.get("agents", [])),
            "snapshot": snapshot,
        }
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def bootstrap_vault(
    config: dict[str, Any],
    *,
    prompt_fn: Any | None = None,
    require_tty: bool = True,
) -> CredentialVault:
    prompt = prompt_fn or getpass.getpass
    vault = CredentialVault(config["_credentials_path"])
    if require_tty and not sys.stdin.isatty():
        raise RuntimeError("A terminal is required to unlock the credential vault")
    if not vault.exists():
        first = prompt("Set master password: ")
        second = prompt("Confirm master password: ")
        if not first:
            raise ValueError("Master password cannot be empty")
        if first != second:
            raise ValueError("Master passwords do not match")
        vault.create(first)
        return vault
    password = prompt("Enter master password: ")
    vault.unlock(password)
    return vault


def utc_now_ts() -> float:
    return time.time()


def iso_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_json_loads(s: str) -> Any:
    try:
        return json.loads(s)
    except Exception:
        return None


def parse_iso_ts(value: str | None) -> float | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except Exception:
        return None


def relative_age(age_sec: float | None) -> str:
    if age_sec is None:
        return "n/a"
    if age_sec < 60:
        return f"{int(age_sec)}s"
    if age_sec < 3600:
        return f"{int(age_sec // 60)}m"
    if age_sec < 86400:
        return f"{int(age_sec // 3600)}h"
    return f"{int(age_sec // 86400)}d"


def truncate(text: str | None, limit: int = 240) -> str:
    if not text:
        return ""
    one = " ".join(str(text).split())
    return one if len(one) <= limit else one[: limit - 1] + "…"


def expand_path(path: str | None) -> str | None:
    if not path:
        return None
    return os.path.expanduser(path)


def git_branch(cwd: str | None) -> str | None:
    if not cwd or not os.path.isdir(cwd):
        return None
    try:
        proc = subprocess.run(
            ["git", "-C", cwd, "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=2,
        )
        if proc.returncode == 0:
            branch = proc.stdout.strip()
            return branch or None
    except Exception:
        pass
    return None


def readlink_cwd(pid: int) -> str | None:
    try:
        if _IS_MACOS:
            return _psutil.Process(pid).cwd()
        return os.readlink(f"/proc/{pid}/cwd")
    except Exception:
        return None


def get_process_env(pid: int) -> dict[str, str]:
    try:
        if _IS_MACOS:
            return dict(_psutil.Process(pid).environ())
        raw = Path(f"/proc/{pid}/environ").read_bytes()
        env: dict[str, str] = {}
        for item in raw.split(b"\x00"):
            if b"=" not in item:
                continue
            key, value = item.split(b"=", 1)
            env[key.decode(errors="ignore")] = value.decode(errors="ignore")
        return env
    except Exception:
        return {}


def get_cmux_context(pid: int) -> dict[str, str] | None:
    env = get_process_env(pid)
    workspace_id = env.get("CMUX_WORKSPACE_ID")
    surface_id = env.get("CMUX_SURFACE_ID")
    if not workspace_id or not surface_id:
        return None
    return {"workspace_id": workspace_id, "surface_id": surface_id}


def list_cmux_workspace_names() -> dict[str, str]:
    try:
        proc = subprocess.run(
            ["cmux", "list-workspaces", "--id-format", "both"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return {}
    if proc.returncode != 0:
        return {}

    names: dict[str, str] = {}
    uuid_re = re.compile(r"\b[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}\b", re.IGNORECASE)
    for raw_line in proc.stdout.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        match = uuid_re.search(line)
        if not match:
            continue
        workspace_id = match.group(0)
        title = line[match.end():].strip()
        title = re.sub(r"\s+\[selected\]$", "", title).strip()
        if title:
            names[workspace_id] = title
    return names


def list_cmux_process_contexts() -> dict[int, dict[str, str]]:
    try:
        proc = subprocess.run(
            ["cmux", "top", "--all", "--processes", "--flat", "--format", "tsv"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except Exception:
        return {}
    if proc.returncode != 0:
        return {}

    direct_contexts: dict[int, dict[str, str]] = defaultdict(dict)
    parent_pids: dict[int, int] = {}
    tag_re = re.compile(
        r"workspace:([0-9A-F-]+):tag:codex\.([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
        re.IGNORECASE,
    )
    surface_re = re.compile(r"^surface:(\d+)$", re.IGNORECASE)
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 6 or parts[3] != "process":
            continue
        try:
            pid = int(parts[4])
        except ValueError:
            continue
        parent = parts[5]
        tag_match = tag_re.search(parent)
        if tag_match:
            direct_contexts[pid]["workspace_id"] = tag_match.group(1)
            direct_contexts[pid]["session_id"] = tag_match.group(2)
        surface_match = surface_re.match(parent)
        if surface_match:
            direct_contexts[pid]["surface_ref"] = parent
        else:
            try:
                parent_pids[pid] = int(parent)
            except ValueError:
                pass

    resolved: dict[int, dict[str, str]] = {}

    def resolve(pid: int, seen: set[int] | None = None) -> dict[str, str]:
        if pid in resolved:
            return resolved[pid]
        if seen is None:
            seen = set()
        if pid in seen:
            return dict(direct_contexts.get(pid, {}))
        seen.add(pid)

        context = dict(direct_contexts.get(pid, {}))
        parent_pid = parent_pids.get(pid)
        if parent_pid is not None:
            parent_context = resolve(parent_pid, seen)
            for key, value in parent_context.items():
                context.setdefault(key, value)
        resolved[pid] = context
        return context

    for pid in set(direct_contexts) | set(parent_pids):
        resolve(pid)
    return {pid: ctx for pid, ctx in resolved.items() if ctx}


def infer_agent_type(args: str) -> str:
    try:
        tokens = shlex.split(args)
    except Exception:
        tokens = str(args).split()
    if not tokens:
        return ""
    arg_text = str(args).lower()
    if any(
        marker in arg_text
        for marker in (
            "codex computer use",
            "skycomputeruseclient",
            "node_repl",
        )
    ):
        return ""
    lowered = [token.lower() for token in tokens]
    basenames = [Path(token).name.lower() for token in tokens]

    codex_indexes = [
        i for i, name in enumerate(basenames)
        if name == "codex" and (i == 0 or lowered[i - 1] not in {"--source", "--agent"})
    ]
    if codex_indexes:
        if "app-server" in lowered:
            return ""
        return "codex"

    if "claude" in basenames:
        if "--output-format" in lowered and "--input-format" in lowered and "stream-json" in lowered:
            return ""
        return "claude"

    if "droid" in basenames:
        # Skip droid exec subprocesses
        if "exec" in lowered and "--input-format" in lowered and "stream-jsonrpc" in lowered:
            return ""
        return "droid"

    return ""


def extract_codex_session_id(args: str) -> str | None:
    try:
        tokens = shlex.split(args)
    except Exception:
        tokens = str(args).split()
    if "resume" not in tokens:
        return None
    uuid_re = re.compile(
        r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
        re.IGNORECASE,
    )
    for token in tokens[tokens.index("resume") + 1:]:
        if uuid_re.match(token):
            return token
    return None


def get_recent_files(root: str | None, pattern: str = "*.jsonl", limit: int = 120, include_subdirs: bool = True) -> list[Path]:
    if not root:
        return []
    base = Path(expand_path(root))
    if not base.exists():
        return []
    globber = base.rglob(pattern) if include_subdirs else base.glob(pattern)
    files = [p for p in globber if p.is_file()]
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:limit]


def extract_codex_message(payload: dict[str, Any]) -> str | None:
    ptype = payload.get("type")
    if ptype == "message" and payload.get("role") == "assistant":
        parts = []
        for item in payload.get("content", []):
            if item.get("type") in {"output_text", "text"} and item.get("text"):
                parts.append(item["text"])
        if parts:
            return " ".join(parts)
    if ptype == "function_call":
        name = payload.get("name")
        if name:
            return f"tool:{name}"
    return None


def extract_codex_pending(payload: dict[str, Any]) -> list[str]:
    if payload.get("type") != "function_call" or payload.get("name") != "update_plan":
        return []
    data = safe_json_loads(payload.get("arguments", ""))
    if not isinstance(data, dict):
        return []
    pending = []
    for item in data.get("plan", []):
        if item.get("status") != "completed":
            status = item.get("status", "pending")
            step = item.get("step", "")
            pending.append(f"[{status}] {step}".strip())
    return pending


def parse_codex_session(path: Path) -> dict[str, Any] | None:
    meta = {
        "session_id": None,
        "cwd": None,
        "start_ts": None,
        "heartbeat_ts": path.stat().st_mtime,
        "recent_output": "",
        "pending_items": [],
        "last_user_message": "",
        "source_file": str(path),
        "session_kind": "main",
        "model": None,
        "needs_user": False,
        "has_result": False,
    }
    tail: deque[str] = deque(maxlen=300)
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            first = f.readline()
            if first:
                obj = safe_json_loads(first)
                if isinstance(obj, dict) and obj.get("type") == "session_meta":
                    payload = obj.get("payload", {})
                    meta["session_id"] = payload.get("id")
                    meta["cwd"] = payload.get("cwd")
                    meta["start_ts"] = parse_iso_ts(payload.get("timestamp")) or parse_iso_ts(obj.get("timestamp"))
                    meta["heartbeat_ts"] = parse_iso_ts(obj.get("timestamp")) or meta["heartbeat_ts"]
                    if payload.get("thread_source") == "subagent" or isinstance(payload.get("source"), dict):
                        if isinstance(payload.get("source"), dict) and payload["source"].get("subagent"):
                            meta["session_kind"] = "subagent"
                tail.append(first)
            for line in f:
                obj = safe_json_loads(line)
                if isinstance(obj, dict) and obj.get("type") == "turn_context":
                    payload = obj.get("payload", {})
                    model = payload.get("model")
                    if model:
                        meta["model"] = model
                    if model == "codex-auto-review":
                        meta["session_kind"] = "approval_review"
                tail.append(line)
    except Exception:
        return None

    pending: list[str] = []
    recent_text = ""
    recent_tool = ""
    last_user = ""
    last_ts = meta["heartbeat_ts"]
    last_user_ts = None
    last_agent_ts = None
    last_agent_phase = ""
    for line in reversed(tail):
        obj = safe_json_loads(line)
        if not isinstance(obj, dict):
            continue
        ts = parse_iso_ts(obj.get("timestamp"))
        if ts and (last_ts is None or ts > last_ts):
            last_ts = ts
        if obj.get("type") == "event_msg":
            ep = obj.get("payload", {})
            if ep.get("type") == "agent_message" and not recent_text:
                recent_text = ep.get("message", "")
                last_agent_ts = ts or last_agent_ts
                last_agent_phase = ep.get("phase", "") or last_agent_phase
        elif obj.get("type") == "response_item":
            candidate = extract_codex_message(obj.get("payload", {})) or ""
            if candidate and candidate.startswith("tool:"):
                if not recent_tool:
                    recent_tool = candidate
                continue
            elif candidate and not recent_text:
                recent_text = candidate
                last_agent_ts = ts or last_agent_ts
                last_agent_phase = obj.get("payload", {}).get("phase", "") or last_agent_phase
        if not last_user and obj.get("type") == "event_msg":
            ep = obj.get("payload", {})
            if ep.get("type") == "user_message":
                last_user = ep.get("message", "")
                last_user_ts = ts or last_user_ts
        if not pending and obj.get("type") == "response_item":
            pending = extract_codex_pending(obj.get("payload", {}))

    needs_user = False
    for pattern in DEFAULT_CONFIG["status"]["needs_input_patterns"]:
        try:
            if recent_text and re.search(pattern, recent_text, re.IGNORECASE):
                needs_user = True
                break
        except re.error:
            continue
    has_result = bool(
        recent_text
        and last_agent_ts
        and (last_user_ts is None or last_agent_ts >= last_user_ts)
        and last_agent_phase == "final_answer"
    )

    if recent_text:
        recent_output = recent_text
    elif recent_tool and last_user:
        recent_output = f"{truncate(last_user, 180)}\n\n当前动作: {recent_tool}"
    else:
        recent_output = recent_tool
    meta["recent_output"] = truncate(recent_output)
    if not pending and needs_user:
        pending = ["需要你回话"]
    elif not pending and has_result:
        pending = ["有新结果待查看"]
    meta["pending_items"] = pending
    meta["last_user_message"] = truncate(last_user, 180)
    meta["heartbeat_ts"] = last_ts
    meta["needs_user"] = needs_user
    meta["has_result"] = has_result
    return meta


def extract_claude_assistant_text(obj: dict[str, Any]) -> str | None:
    if obj.get("type") == "summary" and obj.get("summary"):
        return obj["summary"]
    if obj.get("type") == "assistant":
        message = obj.get("message", {})
        content = message.get("content", [])
        if isinstance(content, str):
            return content
        parts = []
        for item in content:
            if item.get("type") == "text" and item.get("text"):
                parts.append(item["text"])
        if parts:
            return " ".join(parts)
    if obj.get("type") == "last-prompt":
        return obj.get("lastPrompt")
    return None


def parse_claude_todos(session_id: str, todos_root: str | None, tasks_root: str | None) -> list[str]:
    items: list[str] = []
    if tasks_root:
        task_dir = Path(expand_path(tasks_root)) / session_id
        if task_dir.exists():
            for path in sorted(task_dir.glob("*.json")):
                data = safe_json_loads(path.read_text(encoding="utf-8", errors="ignore"))
                if isinstance(data, dict) and data.get("status") != "completed":
                    subject = data.get("activeForm") or data.get("subject") or path.name
                    items.append(f"[{data.get('status', 'pending')}] {subject}")
    if todos_root:
        root = Path(expand_path(todos_root))
        for path in root.glob(f"{session_id}-agent-*.json"):
            data = safe_json_loads(path.read_text(encoding="utf-8", errors="ignore"))
            if isinstance(data, list):
                for item in data:
                    if isinstance(item, dict) and item.get("status") != "completed":
                        subject = item.get("activeForm") or item.get("content") or "todo"
                        items.append(f"[{item.get('status', 'pending')}] {subject}")
    deduped = []
    seen = set()
    for item in items:
        if item not in seen:
            deduped.append(item)
            seen.add(item)
    return deduped[:8]


def parse_claude_session(path: Path, todos_root: str | None, tasks_root: str | None) -> dict[str, Any] | None:
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return None
    if not lines:
        return None

    session_id = path.stem
    cwd = None
    start_ts = None
    heartbeat_ts = path.stat().st_mtime
    recent_output = ""
    last_user = ""
    git_branch = None

    for raw in lines:
        obj = safe_json_loads(raw)
        if not isinstance(obj, dict):
            continue
        ts = parse_iso_ts(obj.get("timestamp"))
        if ts:
            heartbeat_ts = max(heartbeat_ts, ts)
            if start_ts is None or ts < start_ts:
                start_ts = ts
        if not cwd and obj.get("cwd"):
            cwd = obj.get("cwd")
        if not git_branch and obj.get("gitBranch"):
            git_branch = obj.get("gitBranch")

    for raw in reversed(lines[-80:]):
        obj = safe_json_loads(raw)
        if not isinstance(obj, dict):
            continue
        if not recent_output:
            recent_output = extract_claude_assistant_text(obj) or recent_output
        if not last_user and obj.get("type") == "user":
            msg = obj.get("message", {})
            content = msg.get("content")
            if isinstance(content, str):
                last_user = content

    pending_items = parse_claude_todos(session_id, todos_root, tasks_root)
    if not pending_items and last_user:
        pending_items = [truncate(last_user, 180)]

    return {
        "session_id": session_id,
        "cwd": cwd,
        "start_ts": start_ts,
        "heartbeat_ts": heartbeat_ts,
        "recent_output": truncate(recent_output),
        "pending_items": pending_items,
        "last_user_message": truncate(last_user, 180),
        "git_branch": git_branch,
        "source_file": str(path),
    }


def parse_droid_session(path: Path) -> dict[str, Any] | None:
    """Parse Factory Droid session file (.jsonl format)."""
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return None
    if not lines:
        return None

    session_id = path.stem
    cwd = None
    start_ts = None
    heartbeat_ts = path.stat().st_mtime
    recent_output = ""
    last_user = ""
    pending_items = []

    # Parse first line for session_start
    first_obj = safe_json_loads(lines[0])
    if isinstance(first_obj, dict) and first_obj.get("type") == "session_start":
        session_id = first_obj.get("id") or session_id
        cwd = first_obj.get("cwd")
        start_ts = parse_iso_ts(first_obj.get("timestamp"))

    # Scan all lines for timestamps and metadata
    for raw in lines:
        obj = safe_json_loads(raw)
        if not isinstance(obj, dict):
            continue
        
        ts = parse_iso_ts(obj.get("timestamp"))
        if ts:
            heartbeat_ts = max(heartbeat_ts, ts)
            if start_ts is None or ts < start_ts:
                start_ts = ts
        
        # Extract cwd from messages if not found
        if not cwd and obj.get("type") == "message":
            msg = obj.get("message", {})
            if isinstance(msg, dict):
                content = msg.get("content", [])
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text":
                            text = item.get("text", "")
                            # Try to extract cwd from system-reminder
                            if "% pwd" in text and "\n/" in text:
                                for line in text.split("\n"):
                                    if line.startswith("/") and not line.startswith("/ "):
                                        cwd = line.strip()
                                        break

    # Parse recent messages for output and user input
    for raw in reversed(lines[-80:]):
        obj = safe_json_loads(raw)
        if not isinstance(obj, dict) or obj.get("type") != "message":
            continue
        
        msg = obj.get("message", {})
        if not isinstance(msg, dict):
            continue
        
        role = msg.get("role")
        content = msg.get("content", [])
        
        # Extract assistant's recent output
        if role == "assistant" and not recent_output:
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict):
                        if item.get("type") == "text" and item.get("text"):
                            recent_output = item["text"]
                            break
                        elif item.get("type") == "tool_use":
                            # Agent is working (using tools)
                            tool_name = item.get("name", "")
                            recent_output = f"[Using tool: {tool_name}]"
                            break
        
        # Extract user's last message
        if role == "user" and not last_user:
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text = item.get("text", "")
                        # Skip system reminders
                        if not text.startswith("<system-reminder>"):
                            last_user = text
                            break

    # Check for pending work (AskUser, waiting patterns)
    if recent_output:
        # Check if recent output indicates waiting for user input
        waiting_indicators = [
            "AskUser",
            "Would you like",
            "Do you want",
            "Should I",
            "Shall I",
            "Please confirm",
            "Please provide",
            "which option",
            "Let me know"
        ]
        for indicator in waiting_indicators:
            if indicator.lower() in recent_output.lower():
                pending_items.append(truncate(recent_output, 180))
                break

    return {
        "session_id": session_id,
        "cwd": cwd,
        "start_ts": start_ts,
        "heartbeat_ts": heartbeat_ts,
        "recent_output": truncate(recent_output),
        "pending_items": pending_items or ([truncate(last_user, 180)] if last_user else []),
        "last_user_message": truncate(last_user, 180),
        "source_file": str(path),
    }


@dataclass
class ProcInfo:
    pid: int
    ppid: int
    stat: str
    etimes: int
    cpu: float
    mem: float
    args: str
    cwd: str | None
    agent_type: str
    start_ts: float
    session_id: str | None = None
    command_session_id: str | None = None
    cmux_session_id: str | None = None
    cmux_workspace_id: str | None = None
    cmux_surface_ref: str | None = None
    cmux_surface_id: str | None = None
    match_source: str | None = None
    override_alias: str | None = None


def _parse_etime(s: str) -> int:
    """Parse macOS ps etime format [[DD-]HH:]MM:SS into total seconds."""
    try:
        s = s.strip()
        days = 0
        if "-" in s:
            d, s = s.split("-", 1)
            days = int(d)
        parts = s.split(":")
        if len(parts) == 3:
            h, m, sec = int(parts[0]), int(parts[1]), int(parts[2])
        elif len(parts) == 2:
            h, m, sec = 0, int(parts[0]), int(parts[1])
        else:
            return 0
        return days * 86400 + h * 3600 + m * 60 + sec
    except Exception:
        return 0


def list_processes() -> list[ProcInfo]:
    if _IS_MACOS:
        cmd = ["ps", "-e", "-o", "pid=,ppid=,state=,etime=,pcpu=,pmem=,command="]
    else:
        cmd = ["ps", "-e", "-o", "pid=", "-o", "ppid=", "-o", "stat=",
               "-o", "etimes=", "-o", "pcpu=", "-o", "pmem=", "-o", "args="]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
    cmux_contexts = list_cmux_process_contexts() if _IS_MACOS else {}
    now = utc_now_ts()
    entries: list[ProcInfo] = []
    for line in proc.stdout.splitlines():
        parts = line.strip().split(None, 6)
        if len(parts) < 7:
            continue
        pid, ppid, stat, etimes, cpu, mem, args = parts
        agent_type = infer_agent_type(args)
        if not agent_type:
            continue
        try:
            et = _parse_etime(etimes) if _IS_MACOS else int(float(etimes))
        except Exception:
            et = 0
        pid_int = int(pid)
        cmux_context = cmux_contexts.get(pid_int, {})
        command_session_id = extract_codex_session_id(args) if agent_type == "codex" else None
        cmux_session_id = cmux_context.get("session_id")
        entries.append(
            ProcInfo(
                pid=pid_int,
                ppid=int(ppid),
                stat=stat,
                etimes=et,
                cpu=float(cpu),
                mem=float(mem),
                args=args,
                cwd=readlink_cwd(pid_int),
                agent_type=agent_type,
                start_ts=now - et,
                session_id=cmux_session_id or command_session_id,
                command_session_id=command_session_id,
                cmux_session_id=cmux_session_id,
                cmux_workspace_id=cmux_context.get("workspace_id"),
                cmux_surface_ref=cmux_context.get("surface_ref"),
                match_source="cmux_tag" if cmux_session_id else ("command_resume" if command_session_id else None),
            )
        )
    return entries


def dedupe_processes(entries: list[ProcInfo]) -> list[ProcInfo]:
    matched = {p.pid: p for p in entries}
    roots = []
    for p in entries:
        parent = matched.get(p.ppid)
        if parent and parent.agent_type == p.agent_type:
            continue
        roots.append(p)
    roots.sort(key=lambda p: p.start_ts)
    return roots


def _normalize_session_override(value: Any) -> dict[str, str]:
    if isinstance(value, str):
        return {"session_id": value}
    if isinstance(value, dict):
        session_id = value.get("session_id") or value.get("id")
        if session_id:
            out = {"session_id": str(session_id)}
            if value.get("alias"):
                out["alias"] = str(value["alias"])
            return out
    return {}


def apply_session_overrides(
    processes: list[ProcInfo],
    config: dict[str, Any],
    workspace_names: dict[str, str] | None = None,
) -> dict[int, dict[str, str]]:
    overrides = config.get("session_overrides") or {}
    if not isinstance(overrides, dict):
        return {}
    workspace_names = workspace_names or {}
    applied: dict[int, dict[str, str]] = {}

    for proc in processes:
        workspace_name = workspace_names.get(proc.cmux_workspace_id or "")
        keys = [
            f"pid:{proc.pid}",
            f"cmux_surface:{proc.cmux_surface_id}",
            f"cmux_surface:{proc.cmux_surface_ref}",
            f"cmux_workspace:{proc.cmux_workspace_id}",
            f"cmux_workspace_name:{workspace_name}",
        ]
        for key in keys:
            if key.endswith(":None") or key.endswith(":"):
                continue
            override = _normalize_session_override(overrides.get(key))
            if not override:
                continue
            proc.session_id = override["session_id"]
            proc.match_source = "manual_override"
            proc.override_alias = override.get("alias")
            applied[proc.pid] = override
            break
    return applied


def _binding_keys_for_values(surface_id: str | None = None, surface_ref: str | None = None) -> list[str]:
    keys = []
    if surface_id:
        keys.append(f"cmux_surface:{surface_id}")
    if surface_ref:
        keys.append(f"cmux_surface_ref:{surface_ref}")
    return keys


def session_binding_keys_for_proc(proc: ProcInfo) -> list[str]:
    return _binding_keys_for_values(proc.cmux_surface_id, proc.cmux_surface_ref)


def session_binding_keys_for_agent(agent: dict[str, Any]) -> list[str]:
    return _binding_keys_for_values(agent.get("cmux_surface_id"), agent.get("cmux_surface_ref"))


def read_session_bindings(config: dict[str, Any]) -> dict[str, Any]:
    data = read_json_file(config.get("session_bindings_file", BASE_DIR / "session_bindings.json"), {})
    return data if isinstance(data, dict) else {}


def write_session_binding(config: dict[str, Any], agent: dict[str, Any], session_id: str, probe_token: str) -> dict[str, Any]:
    bindings = read_session_bindings(config)
    keys = session_binding_keys_for_agent(agent)
    if not keys:
        raise ValueError("Agent does not expose a CMUX surface for session binding")
    record = {
        "session_id": session_id,
        "verified_at": iso_now(),
        "method": "probe",
        "probe_token": probe_token,
        "pid": agent.get("pid"),
        "cwd": agent.get("cwd"),
        "cmux_workspace_id": agent.get("cmux_workspace_id"),
        "cmux_surface_id": agent.get("cmux_surface_id"),
        "cmux_surface_ref": agent.get("cmux_surface_ref"),
    }
    for key in keys:
        bindings[key] = record
    write_json_file(config.get("session_bindings_file", BASE_DIR / "session_bindings.json"), bindings)
    return record


def apply_session_bindings(processes: list[ProcInfo], config: dict[str, Any]) -> dict[int, dict[str, Any]]:
    bindings = read_session_bindings(config)
    if not bindings:
        return {}
    applied: dict[int, dict[str, Any]] = {}
    for proc in processes:
        if proc.session_id:
            continue
        for key in session_binding_keys_for_proc(proc):
            record = bindings.get(key)
            if not isinstance(record, dict) or not record.get("session_id"):
                continue
            if record.get("pid") is not None and int(record.get("pid")) != proc.pid:
                continue
            if record.get("cwd") and proc.cwd and record.get("cwd") != proc.cwd:
                continue
            proc.session_id = str(record["session_id"])
            proc.match_source = "probe_binding"
            applied[proc.pid] = record
            break
    return applied


def match_sessions(processes: list[ProcInfo], sessions: list[dict[str, Any]]) -> dict[int, dict[str, Any]]:
    by_id = {s.get("session_id"): s for s in sessions if s.get("session_id")}
    by_cwd: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for session in sessions:
        cwd = session.get("cwd")
        if cwd:
            by_cwd[cwd].append(session)
    for group in by_cwd.values():
        group.sort(key=lambda s: s.get("start_ts") or s.get("heartbeat_ts") or 0)

    used: set[str] = set()
    out: dict[int, dict[str, Any]] = {}
    for proc in processes:
        if proc.session_id and proc.session_id in by_id:
            session = by_id[proc.session_id]
            out[proc.pid] = session
            used.add(proc.session_id)
            continue
        cwd = proc.cwd
        if not cwd:
            continue
        candidates = [
            s for s in by_cwd.get(cwd, [])
            if s.get("session_id") not in used and s.get("session_kind") != "approval_review"
        ]
        if not candidates:
            continue
        if proc.agent_type == "codex" and (proc.cmux_workspace_id or proc.cmux_surface_id or proc.cmux_surface_ref):
            if len(candidates) != 1:
                proc.match_source = "ambiguous"
                continue
            best = candidates[0]
            out[proc.pid] = best
            proc.match_source = "cwd_unique"
            if best.get("session_id"):
                used.add(best["session_id"])
            continue
        best = min(
            candidates,
            key=lambda s: abs((s.get("start_ts") or s.get("heartbeat_ts") or proc.start_ts) - proc.start_ts),
        )
        out[proc.pid] = best
        if not proc.match_source:
            proc.match_source = "cwd_time"
        if best.get("session_id"):
            used.add(best["session_id"])
    return out


def detect_parent_application(pid: int) -> dict[str, Any] | None:
    """Detect which application the process is running in."""
    if not _IS_MACOS:
        return None
    
    try:
        proc = _psutil.Process(pid)
        
        # Traverse up to 10 levels in the process tree
        for _ in range(10):
            proc = proc.parent()
            if not proc:
                break
            
            name = proc.name().lower()
            
            # Terminal applications
            if 'terminal' in name and 'app' in name:
                return {"app_name": "Terminal", "app_type": "terminal", "app_pid": proc.pid, "app_icon": "🖥️"}
            elif 'iterm' in name:
                return {"app_name": "iTerm2", "app_type": "terminal", "app_pid": proc.pid, "app_icon": "💻"}
            elif 'ghostty' in name:
                return {"app_name": "Ghostty", "app_type": "terminal", "app_pid": proc.pid, "app_icon": "👻"}
            
            # IDE applications
            elif 'goland' in name:
                return {"app_name": "GoLand", "app_type": "ide", "app_pid": proc.pid, "app_icon": "🐹"}
            elif 'idea' in name and 'jetbrains' not in name:
                return {"app_name": "IntelliJ IDEA", "app_type": "ide", "app_pid": proc.pid, "app_icon": "💡"}
            elif 'pycharm' in name:
                return {"app_name": "PyCharm", "app_type": "ide", "app_pid": proc.pid, "app_icon": "🐍"}
            elif 'webstorm' in name:
                return {"app_name": "WebStorm", "app_type": "ide", "app_pid": proc.pid, "app_icon": "🌐"}
            elif 'clion' in name:
                return {"app_name": "CLion", "app_type": "ide", "app_pid": proc.pid, "app_icon": "🔧"}
            elif 'code' in name or 'visual studio code' in name.lower():
                return {"app_name": "Visual Studio Code", "app_type": "ide", "app_pid": proc.pid, "app_icon": "📝"}
        
        return None
        
    except Exception:
        return None


def focus_window_by_pid(pid: int) -> dict[str, Any]:
    """Focus the window containing the process."""
    if not _IS_MACOS:
        return {"success": False, "error": "Only macOS is supported"}
    
    # Detect the parent application
    app_info = detect_parent_application(pid)
    
    if not app_info:
        # Fallback: try common applications
        return focus_fallback(pid)
    
    app_name = app_info["app_name"]
    
    try:
        # Use simple activate command (more reliable)
        script = f'tell application "{app_name}" to activate'
        
        result = subprocess.run(
            ["osascript", "-e", script],
            capture_output=True,
            text=True,
            timeout=3
        )
        
        if result.returncode == 0:
            return {
                "success": True,
                "pid": pid,
                "app_name": app_name,
                "app_type": app_info["app_type"]
            }
        else:
            return {
                "success": False,
                "error": result.stderr.strip() or "Failed to activate window",
                "app_name": app_name
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "app_name": app_name
        }


def focus_fallback(pid: int) -> dict[str, Any]:
    """Fallback: try to activate common applications."""
    apps = ["Terminal", "iTerm2", "Ghostty", "Visual Studio Code", "GoLand", "IntelliJ IDEA", "PyCharm"]
    
    for app in apps:
        try:
            script = f'''
            tell application "System Events"
                if exists process "{app}" then
                    tell process "{app}"
                        set frontmost to true
                    end tell
                    return true
                end if
            end tell
            return false
            '''
            
            result = subprocess.run(
                ["osascript", "-e", script],
                capture_output=True,
                text=True,
                timeout=3
            )
            
            if result.returncode == 0 and result.stdout.strip() == "true":
                return {"success": True, "pid": pid, "app_name": app, "method": "fallback"}
        except:
            continue
    
    return {"success": False, "error": "No matching application found"}


def infer_status(proc: ProcInfo, session: dict[str, Any] | None, config: dict[str, Any]) -> str:
    now = utc_now_ts()
    cfg = config.get("status", {})
    heartbeat_ts = session.get("heartbeat_ts") if session else None
    heartbeat_age = (now - heartbeat_ts) if heartbeat_ts else None
    recent_output = (session or {}).get("recent_output", "") or ""

    if (session or {}).get("needs_user") or (session or {}).get("has_result"):
        return "needs-input"

    for pattern in cfg.get("needs_input_patterns", []):
        try:
            if re.search(pattern, recent_output, re.IGNORECASE):
                return "needs-input"
        except re.error:
            continue

    if proc.cpu >= float(cfg.get("busy_cpu_threshold", 20.0)) or proc.stat.startswith(("R", "D")):
        return "busy"
    if heartbeat_age is not None and heartbeat_age <= int(cfg.get("active_heartbeat_sec", 120)):
        return "active"
    if heartbeat_age is not None and heartbeat_age >= int(cfg.get("stale_heartbeat_sec", 900)):
        return "stale"
    return "idle"


def summarize_host(config: dict[str, Any], host_cfg: dict[str, Any]) -> dict[str, Any]:
    base_paths = config.get("paths", {})
    host_paths = {**base_paths, **host_cfg.get("paths", {})}

    procs = dedupe_processes(list_processes())
    cmux_workspace_names = list_cmux_workspace_names() if host_cfg.get("mode") == "local" else {}
    if host_cfg.get("mode") == "local" and _IS_MACOS:
        for proc in procs:
            cmux_context = get_cmux_context(proc.pid) or {}
            proc.cmux_workspace_id = proc.cmux_workspace_id or cmux_context.get("workspace_id")
            proc.cmux_surface_id = proc.cmux_surface_id or cmux_context.get("surface_id")
    apply_session_bindings(procs, config)
    apply_session_overrides(procs, config, cmux_workspace_names)

    codex_procs = [p for p in procs if p.agent_type == "codex"]
    claude_procs = [p for p in procs if p.agent_type == "claude"]
    droid_procs = [p for p in procs if p.agent_type == "droid"]

    codex_sessions = []
    for path in get_recent_files(host_paths.get("codex_sessions"), "*.jsonl", config.get("session_scan_limit", 120), True):
        session = parse_codex_session(path)
        if session:
            codex_sessions.append(session)

    claude_sessions = []
    for path in get_recent_files(host_paths.get("claude_projects"), "*.jsonl", config.get("session_scan_limit", 120), True):
        if "subagents" in path.parts:
            continue
        session = parse_claude_session(path, host_paths.get("claude_todos"), host_paths.get("claude_tasks"))
        if session:
            claude_sessions.append(session)

    droid_sessions = []
    for path in get_recent_files(host_paths.get("droid_sessions"), "*.jsonl", config.get("session_scan_limit", 120), True):
        # Skip settings files
        if path.name.endswith(".settings.json"):
            continue
        session = parse_droid_session(path)
        if session:
            droid_sessions.append(session)

    codex_match = match_sessions(codex_procs, codex_sessions)
    claude_match = match_sessions(claude_procs, claude_sessions)
    droid_match = match_sessions(droid_procs, droid_sessions)

    aliases = read_json_file(config.get("aliases_file", BASE_DIR / "session_aliases.json"), {})
    send_template = host_cfg.get("send_command_template") or config.get("send_command_template")
    send_mode = host_cfg.get("send_mode") or config.get("send_mode")
    agents = []
    branch_cache: dict[str, str | None] = {}
    host_id = host_identity(host_cfg)
    for proc in procs:
        if proc.agent_type == "codex":
            session = codex_match.get(proc.pid)
        elif proc.agent_type == "claude":
            session = claude_match.get(proc.pid)
        elif proc.agent_type == "droid":
            session = droid_match.get(proc.pid)
        else:
            session = None
        cmux_context = get_cmux_context(proc.pid) if host_cfg.get("mode") == "local" else None
        cmux_workspace_id = (cmux_context or {}).get("workspace_id") or proc.cmux_workspace_id
        cmux_surface_id = (cmux_context or {}).get("surface_id") or proc.cmux_surface_id
        has_cmux_identity = proc.agent_type == "codex" and (proc.cmux_workspace_id or cmux_workspace_id or proc.cmux_surface_ref or cmux_surface_id)
        if not session and not has_cmux_identity and "+" not in proc.stat and proc.cpu < 0.2:
            continue
        cwd = proc.cwd or (session or {}).get("cwd")
        if cwd not in branch_cache:
            branch_cache[cwd or ""] = (session or {}).get("git_branch") or git_branch(cwd)
        branch = branch_cache[cwd or ""]
        heartbeat_ts = (session or {}).get("heartbeat_ts")
        status = infer_status(proc, session, config)
        
        # Detect parent application (for local hosts only)
        parent_app = None
        if host_cfg.get("mode") == "local" and _IS_MACOS:
            parent_app = detect_parent_application(proc.pid)
        cmux_workspace_name = cmux_workspace_names.get(cmux_workspace_id or "")
        interactive_supported = bool(
            send_template
            or send_mode == "stdin"
            or (send_mode == "cmux" and cmux_workspace_id and cmux_surface_id)
        )
        
        agents.append(
            {
                "id": f"{host_id}:{proc.agent_type}:{proc.pid}",
                "rename_key": f"{host_id}:{proc.agent_type}:{(session or {}).get('session_id') or proc.session_id or (cwd or proc.pid)}",
                "host": host_cfg["name"],
                "host_id": host_id,
                "host_mode": host_cfg.get("mode", "local"),
                "agent_type": proc.agent_type,
                "pid": proc.pid,
                "ppid": proc.ppid,
                "project": os.path.basename(cwd) if cwd else None,
                "display_name": proc.override_alias or aliases.get(f"{host_id}:{proc.agent_type}:{(session or {}).get('session_id') or proc.session_id or (cwd or proc.pid)}"),
                "cwd": cwd,
                "branch": branch,
                "status": status,
                "heartbeat_ts": heartbeat_ts,
                "heartbeat_age_sec": (utc_now_ts() - heartbeat_ts) if heartbeat_ts else None,
                "parent_app": parent_app["app_name"] if parent_app else None,
                "parent_app_icon": parent_app["app_icon"] if parent_app else None,
                "cmux_workspace_id": cmux_workspace_id,
                "cmux_surface_id": cmux_surface_id,
                "cmux_surface_ref": proc.cmux_surface_ref,
                "cmux_workspace_name": cmux_workspace_name,
                "match_source": proc.match_source or "none",
                "uptime_sec": proc.etimes,
                "cpu": proc.cpu,
                "mem": proc.mem,
                "stat": proc.stat,
                "command": truncate(proc.args, 240),
                "recent_output": (session or {}).get("recent_output", ""),
                "pending_items": (session or {}).get("pending_items", []),
                "session_id": (session or {}).get("session_id") or proc.session_id,
                "session_kind": (session or {}).get("session_kind"),
                "needs_user": bool((session or {}).get("needs_user")),
                "has_result": bool((session or {}).get("has_result")),
                "session_file": (session or {}).get("source_file"),
                "last_user_message": (session or {}).get("last_user_message"),
                "interactive_supported": interactive_supported,
                "updated_at": iso_now(),
            }
        )

    counts = Counter(a["status"] for a in agents)
    return {
        "host": host_cfg["name"],
        "host_id": host_id,
        "mode": host_cfg.get("mode", "local"),
        "collected_at": iso_now(),
        "agents": sorted(agents, key=lambda a: (a["status"], a["heartbeat_age_sec"] or 10**12, a["project"] or "")),
        "counts": counts,
    }


def run_ssh_probe(host_cfg: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    source = Path(__file__).read_text(encoding="utf-8")
    payload = base64.b64encode(json.dumps({"config": config, "host": host_cfg}).encode()).decode()
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
            "-o", "GSSAPIAuthentication=yes", "-o", "GSSAPIDelegateCredentials=yes"]
    if host_cfg.get("port"):
        cmd += ["-p", str(host_cfg["port"])]
    if host_cfg.get("identity_file"):
        cmd += ["-i", expand_path(host_cfg["identity_file"])]
    username = host_cfg.get("username", "").strip()
    target = f"{username}@{host_cfg['ssh_target']}" if username else host_cfg["ssh_target"]
    # Try newer python versions first; fall back to python3
    py_cmd = "python3.12 - --probe {p} 2>/dev/null || python3.11 - --probe {p} 2>/dev/null || python3.10 - --probe {p} 2>/dev/null || python3.9 - --probe {p} 2>/dev/null || python3 - --probe {p}".format(p=payload)
    cmd += [target, "/bin/bash", "-lc", py_cmd]
    proc = subprocess.run(cmd, input=source, text=True, capture_output=True, timeout=25)
    if proc.returncode != 0:
        raise RuntimeError(proc.stderr.strip() or proc.stdout.strip() or f"ssh exit {proc.returncode}")
    return json.loads(proc.stdout)


def run_local_shell(template: str, agent: dict[str, Any], message: str) -> dict[str, Any]:
    env = os.environ.copy()
    env.update(
        {
            "AGENT_ID": str(agent.get("id", "")),
            "AGENT_TYPE": str(agent.get("agent_type", "")),
            "AGENT_PID": str(agent.get("pid", "")),
            "AGENT_SESSION_ID": str(agent.get("session_id", "")),
            "AGENT_CWD": str(agent.get("cwd", "")),
            "AGENT_PROJECT": str(agent.get("project", "")),
            "AGENT_BRANCH": str(agent.get("branch", "")),
            "AGENT_MESSAGE": message,
            "AGENT_MESSAGE_B64": base64.b64encode(message.encode("utf-8")).decode(),
        }
    )
    proc = subprocess.run(
        ["/bin/bash", "-lc", template],
        capture_output=True,
        text=True,
        timeout=20,
        env=env,
    )
    return {
        "returncode": proc.returncode,
        "stdout": truncate(proc.stdout, 1000),
        "stderr": truncate(proc.stderr, 1000),
    }


def run_remote_shell(host_cfg: dict[str, Any], template: str, agent: dict[str, Any], message: str) -> dict[str, Any]:
    exports = {
        "AGENT_ID": str(agent.get("id", "")),
        "AGENT_TYPE": str(agent.get("agent_type", "")),
        "AGENT_PID": str(agent.get("pid", "")),
        "AGENT_SESSION_ID": str(agent.get("session_id", "")),
        "AGENT_CWD": str(agent.get("cwd", "")),
        "AGENT_PROJECT": str(agent.get("project", "")),
        "AGENT_BRANCH": str(agent.get("branch", "")),
        "AGENT_MESSAGE": message,
        "AGENT_MESSAGE_B64": base64.b64encode(message.encode("utf-8")).decode(),
    }
    export_str = " ".join(f"{k}={shell_quote(v)}" for k, v in exports.items())
    remote_cmd = f"{export_str} /bin/bash -lc {shell_quote(template)}"
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"]
    if host_cfg.get("port"):
        cmd += ["-p", str(host_cfg["port"])]
    if host_cfg.get("identity_file"):
        cmd += ["-i", expand_path(host_cfg["identity_file"])]
    cmd += [host_cfg["ssh_target"], remote_cmd]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=25)
    return {
        "returncode": proc.returncode,
        "stdout": truncate(proc.stdout, 1000),
        "stderr": truncate(proc.stderr, 1000),
    }


def _ptrace_write_stdin(pid: int, message: bytes) -> int:
    """Inject bytes into pid's stdin fd via ptrace+syscall gadget."""
    import ctypes, ctypes.util, struct as _struct, os as _os
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    PTRACE_ATTACH, PTRACE_DETACH = 16, 17
    PTRACE_GETREGS, PTRACE_SETREGS = 12, 13
    PTRACE_POKEDATA, PTRACE_SINGLESTEP = 5, 9

    class _regs(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in [
            "r15","r14","r13","r12","rbp","rbx","r11","r10","r9","r8",
            "rax","rcx","rdx","rsi","rdi","orig_rax","rip","cs","eflags",
            "rsp","ss","fs_base","gs_base","ds","es","fs","gs"]]

    # find syscall gadget in executable mappings
    syscall_addr = None
    with open(f"/proc/{pid}/maps") as fmaps:
        for line in fmaps:
            if "r-xp" not in line:
                continue
            parts = line.split()
            start, end = [int(x, 16) for x in parts[0].split("-")]
            offset = int(parts[2], 16)
            path = parts[5] if len(parts) > 5 else ""
            if not path or path.startswith("["):
                continue
            try:
                with open(path, "rb") as bf:
                    bf.seek(offset)
                    data = bf.read(end - start)
                idx = data.find(b"\x0f\x05")
                if idx >= 0:
                    syscall_addr = start + idx
                    break
            except Exception:
                continue
    if syscall_addr is None:
        raise RuntimeError("No syscall gadget found")

    r = libc.ptrace(PTRACE_ATTACH, pid, None, None)
    if r < 0:
        raise OSError(ctypes.get_errno(), "PTRACE_ATTACH failed")
    _os.waitpid(pid, 0)

    regs = _regs()
    libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(regs))
    saved = {f: getattr(regs, f) for f, _ in _regs._fields_}

    # write message into stack scratch space
    data_addr = regs.rsp - 256
    padded = message + b"\x00" * (8 - len(message) % 8)
    for i in range(0, len(padded), 8):
        chunk = _struct.unpack("Q", padded[i:i+8])[0]
        libc.ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(data_addr + i), ctypes.c_void_p(chunk))

    regs.rip = syscall_addr
    regs.rax = 1            # SYS_write
    regs.rdi = 0            # fd stdin
    regs.rsi = data_addr
    regs.rdx = len(message)
    libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(regs))
    libc.ptrace(PTRACE_SINGLESTEP, pid, None, None)
    _os.waitpid(pid, 0)

    regs2 = _regs()
    libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(regs2))
    written = regs2.rax

    # restore registers
    for f, _ in _regs._fields_:
        setattr(regs, f, saved[f])
    libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(regs))
    libc.ptrace(PTRACE_DETACH, pid, None, None)
    return written



def _tiocsti_inject(pid: int, message: bytes) -> None:
    """Inject bytes into the PTY input queue via TIOCSTI ioctl.

    Uses ptrace to make the target process call ioctl(0, TIOCSTI, &byte)
    for each byte. This works because the process's own controlling
    terminal check passes (kernel only blocks *external* TIOCSTI).
    """
    import ctypes, ctypes.util, struct as _struct, os as _os
    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    libc.ptrace.restype = ctypes.c_long
    libc.ptrace.argtypes = [ctypes.c_long, ctypes.c_long, ctypes.c_void_p, ctypes.c_void_p]
    PTRACE_ATTACH, PTRACE_DETACH = 16, 17
    PTRACE_GETREGS, PTRACE_SETREGS = 12, 13
    PTRACE_POKEDATA, PTRACE_SINGLESTEP = 5, 9
    TIOCSTI = 0x5412
    SYS_ioctl = 16

    class _regs(ctypes.Structure):
        _fields_ = [(n, ctypes.c_ulonglong) for n in [
            "r15","r14","r13","r12","rbp","rbx","r11","r10","r9","r8",
            "rax","rcx","rdx","rsi","rdi","orig_rax","rip","cs","eflags",
            "rsp","ss","fs_base","gs_base","ds","es","fs","gs"]]

    # find syscall gadget
    syscall_addr = None
    with open(f"/proc/{pid}/maps") as fmaps:
        for line in fmaps:
            if "r-xp" not in line:
                continue
            parts = line.split()
            start, end = [int(x, 16) for x in parts[0].split("-")]
            offset = int(parts[2], 16)
            path = parts[5] if len(parts) > 5 else ""
            if not path or path.startswith("["):
                continue
            try:
                with open(path, "rb") as bf:
                    bf.seek(offset)
                    data = bf.read(end - start)
                idx = data.find(b"\x0f\x05")
                if idx >= 0:
                    syscall_addr = start + idx
                    break
            except Exception:
                continue
    if syscall_addr is None:
        raise RuntimeError("No syscall gadget found in target process")

    r = libc.ptrace(PTRACE_ATTACH, pid, None, None)
    if r < 0:
        raise OSError(ctypes.get_errno(), f"PTRACE_ATTACH failed on pid {pid}")
    _os.waitpid(pid, 0)

    regs = _regs()
    libc.ptrace(PTRACE_GETREGS, pid, None, ctypes.byref(regs))
    saved = {f: getattr(regs, f) for f, _ in _regs._fields_}

    scratch = regs.rsp - 256  # scratch byte location on target's stack

    try:
        for byte in message:
            # Write the byte into scratch memory
            libc.ptrace(PTRACE_POKEDATA, pid, ctypes.c_void_p(scratch),
                        ctypes.c_void_p(int(byte)))
            # ioctl(fd=0, TIOCSTI, &byte)
            regs.rip = syscall_addr
            regs.rax = SYS_ioctl
            regs.rdi = 0          # fd = stdin (the controlling TTY)
            regs.rsi = TIOCSTI
            regs.rdx = scratch    # pointer to the byte
            libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(regs))
            libc.ptrace(PTRACE_SINGLESTEP, pid, None, None)
            _os.waitpid(pid, 0)
    finally:
        # Restore registers and detach regardless of errors
        for f, _ in _regs._fields_:
            setattr(regs, f, saved[f])
        libc.ptrace(PTRACE_SETREGS, pid, None, ctypes.byref(regs))
        libc.ptrace(PTRACE_DETACH, pid, None, None)


def _get_tmux_pane(pid: int) -> str | None:
    """Read TMUX_PANE from process environ; walk up to parent if not found."""
    if _IS_MACOS:
        cur = pid
        for _ in range(6):
            try:
                env = _psutil.Process(cur).environ()
                if "TMUX_PANE" in env:
                    return env["TMUX_PANE"]
                cur = _psutil.Process(cur).ppid()
            except Exception:
                break
        return None
    # Linux: read from /proc
    cur = pid
    for _ in range(6):
        try:
            raw = open(f"/proc/{cur}/environ", "rb").read()
            for item in raw.split(b"\x00"):
                if item.startswith(b"TMUX_PANE="):
                    return item[len(b"TMUX_PANE="):].decode()
        except Exception:
            pass
        # walk up
        try:
            with open(f"/proc/{cur}/status") as f:
                for line in f:
                    if line.startswith("PPid:"):
                        cur = int(line.split()[1])
                        break
                else:
                    break
        except Exception:
            break
    return None


def _send_via_tmux(pane_id: str, message: str) -> dict:
    """Send message + CR to a tmux pane using literal mode."""
    # Send text + \r (real carriage-return) as one literal sequence.
    # This is what the terminal actually sees when the user presses Enter.
    r = subprocess.run(
        ["tmux", "send-keys", "-t", pane_id, "-l", message + "\r"],
        capture_output=True, text=True, timeout=10,
    )
    return {
        "returncode": r.returncode,
        "stdout": truncate(r.stdout, 500),
        "stderr": truncate(r.stderr, 500),
    }


def send_via_cmux_local(agent: dict[str, Any], message: str) -> dict[str, Any]:
    workspace_id = agent.get("cmux_workspace_id")
    surface_id = agent.get("cmux_surface_id")
    if not workspace_id or not surface_id:
        return {
            "returncode": 1,
            "stdout": "",
            "stderr": "cmux mode requires CMUX_WORKSPACE_ID and CMUX_SURFACE_ID in the agent process environment",
        }

    send_cmd = [
        "cmux",
        "send",
        "--workspace",
        str(workspace_id),
        "--surface",
        str(surface_id),
        message,
    ]
    enter_cmd = [
        "cmux",
        "send-key",
        "--workspace",
        str(workspace_id),
        "--surface",
        str(surface_id),
        "Enter",
    ]

    first = subprocess.run(send_cmd, capture_output=True, text=True, timeout=10)
    if first.returncode != 0:
        return {
            "returncode": first.returncode,
            "stdout": truncate(first.stdout, 500),
            "stderr": truncate(first.stderr, 500),
        }

    second = subprocess.run(enter_cmd, capture_output=True, text=True, timeout=10)
    return {
        "returncode": second.returncode,
        "stdout": truncate((first.stdout or "") + (second.stdout or ""), 500),
        "stderr": truncate((first.stderr or "") + (second.stderr or ""), 500),
    }


def send_via_stdin_local(agent: dict[str, Any], message: str) -> dict[str, Any]:
    pid = int(agent["pid"])
    payload = (message + "\r").encode()
    if _IS_MACOS:
        # macOS: tmux send-keys only (ptrace/TIOCSTI not available)
        pane_id = _get_tmux_pane(pid)
        if pane_id:
            return _send_via_tmux(pane_id, message)
        return {"returncode": 1, "stdout": "",
                "stderr": "macOS: agent must run inside tmux (TMUX_PANE not found)"}
    # Linux path
    # 1. Try TIOCSTI via ptrace — pushes bytes into PTY input queue
    try:
        _tiocsti_inject(pid, payload)
        return {"returncode": 0, "stdout": "", "stderr": ""}
    except Exception as exc1:
        pass
    # 2. Try tmux send-keys (if process runs inside tmux)
    pane_id = _get_tmux_pane(pid)
    if pane_id:
        result = _send_via_tmux(pane_id, message)
        if result["returncode"] == 0:
            return result
    # 3. Fallback: ptrace write to stdin fd
    try:
        written = _ptrace_write_stdin(pid, payload)
        if written <= 0:
            return {"returncode": 1, "stdout": "", "stderr": f"ptrace write returned {written}"}
        return {"returncode": 0, "stdout": "", "stderr": ""}
    except Exception as exc3:
        return {"returncode": 1, "stdout": "", "stderr": f"tiocsti: {exc1}; ptrace: {exc3}"}


def send_via_stdin_remote(host_cfg: dict[str, Any], agent: dict[str, Any], message: str) -> dict[str, Any]:
    pid = int(agent["pid"])
    payload_b64 = base64.b64encode((message + "\r").encode()).decode()
    # Inject via TIOCSTI directly on the remote host (opens PTY slave and injects each byte)
    script = (
        "import base64,fcntl,os\n"
        f"payload=base64.b64decode('{payload_b64}')\n"
        f"pid={pid}\n"
        "TIOCSTI=0x5412\n"
        "slave=os.readlink(f'/proc/{pid}/fd/0')\n"
        "f=open(slave,'rb',buffering=0)\n"
        "for b in payload:fcntl.ioctl(f,TIOCSTI,bytes([b]))\n"
        "f.close()\n"
        "print('ok')\n"
    )
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
           "-o", "GSSAPIAuthentication=yes", "-o", "GSSAPIDelegateCredentials=yes"]
    if host_cfg.get("port"):
        cmd += ["-p", str(host_cfg["port"])]
    if host_cfg.get("identity_file"):
        cmd += ["-i", expand_path(host_cfg["identity_file"])]
    username = host_cfg.get("username", "").strip()
    target = f"{username}@{host_cfg['ssh_target']}" if username else host_cfg["ssh_target"]
    cmd += [target, "python3", "-c", script]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    return {
        "returncode": proc.returncode,
        "stdout": truncate(proc.stdout, 1000),
        "stderr": truncate(proc.stderr, 1000),
    }


def collect_all(config: dict[str, Any], vault: CredentialVault | None = None) -> dict[str, Any]:
    hosts = []
    for host_cfg in configured_hosts(config, vault):
        try:
            if host_cfg.get("mode", "local") == "local":
                snap = summarize_host(config, host_cfg)
            elif host_cfg.get("mode") == "ssh_password":
                if vault is None:
                    raise RuntimeError("Credential vault is unavailable")
                creds = vault.get(host_identity(host_cfg))
                if not creds or not creds.get("password") or not creds.get("username"):
                    raise RuntimeError("Credentials are missing for this host")
                snap = run_ssh_probe_password(host_cfg, creds, config)
            else:
                snap = run_ssh_probe(host_cfg, config)
            hosts.append(snap)
        except Exception as exc:
            hosts.append(
                {
                    "host_id": host_identity(host_cfg),
                    "host": host_cfg["name"],
                    "mode": host_cfg.get("mode", "local"),
                    "collected_at": iso_now(),
                    "agents": [],
                    "counts": {},
                    "error": f"{type(exc).__name__}: {exc}",
                    "traceback": traceback.format_exc(),
                }
            )
    all_agents = [agent for host in hosts for agent in host.get("agents", [])]
    totals = Counter(a["status"] for a in all_agents)
    return {
        "generated_at": iso_now(),
        "hosts": hosts,
        "totals": totals,
        "agent_count": len(all_agents),
    }


class SnapshotStore:
    def __init__(self, config: dict[str, Any], vault: CredentialVault | None = None):
        self.config = config
        self.vault = vault
        self.lock = threading.Lock()
        self.snapshot: dict[str, Any] = {"generated_at": None, "hosts": [], "totals": {}, "agent_count": 0}
        self.refreshing = False
        self.last_error = None

    def refresh(self) -> None:
        with self.lock:
            if self.refreshing:
                return
            self.refreshing = True
        try:
            snap = collect_all(self.config, self.vault)
            with self.lock:
                self.snapshot = snap
                self.last_error = None
        except Exception as exc:
            with self.lock:
                self.last_error = f"{type(exc).__name__}: {exc}"
        finally:
            with self.lock:
                self.refreshing = False

    def get(self) -> dict[str, Any]:
        with self.lock:
            return {
                **self.snapshot,
                "refreshing": self.refreshing,
                "last_error": self.last_error,
                "refresh_interval_sec": self.config.get("refresh_interval_sec", 10),
                "dashboard": self.config.get("dashboard", {}),
            }

    def all_agents(self) -> list[dict[str, Any]]:
        with self.lock:
            return [agent for host in self.snapshot.get("hosts", []) for agent in host.get("agents", [])]

    def find_agent(self, agent_id: str) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        with self.lock:
            for host_cfg in configured_hosts(self.config, self.vault):
                for host in self.snapshot.get("hosts", []):
                    if host.get("host_id") != host_identity(host_cfg):
                        continue
                    for agent in host.get("agents", []):
                        if agent.get("id") == agent_id:
                            return agent, host_cfg
        return None, None


def get_aliases(config: dict[str, Any]) -> dict[str, str]:
    return read_json_file(config.get("aliases_file", BASE_DIR / "session_aliases.json"), {})


def set_alias(config: dict[str, Any], rename_key: str, value: str | None) -> dict[str, str]:
    aliases = get_aliases(config)
    if value:
        aliases[rename_key] = value
    else:
        aliases.pop(rename_key, None)
    write_json_file(config.get("aliases_file", BASE_DIR / "session_aliases.json"), aliases)
    return aliases


def send_agent_action(store: SnapshotStore, agent_id: str, message: str) -> dict[str, Any]:
    agent, host_cfg = store.find_agent(agent_id)
    if not agent or not host_cfg:
        raise ValueError("Agent not found")
    send_mode = host_cfg.get("send_mode") or store.config.get("send_mode")
    template = host_cfg.get("send_command_template") or store.config.get("send_command_template")
    if send_mode == "stdin":
        if host_cfg.get("mode", "local") == "local":
            result = send_via_stdin_local(agent, message)
        elif host_cfg.get("mode") == "ssh_password":
            if store.vault is None:
                raise ValueError("Credential vault is unavailable")
            creds = store.vault.get(host_identity(host_cfg))
            if not creds:
                raise ValueError("Credentials are missing for this host")
            result = send_via_stdin_remote_password(host_cfg, creds, agent, message)
        else:
            result = send_via_stdin_remote(host_cfg, agent, message)
    elif send_mode == "cmux":
        if host_cfg.get("mode", "local") != "local":
            raise ValueError("send_mode=cmux is only supported for local hosts")
        result = send_via_cmux_local(agent, message)
    elif template:
        if host_cfg.get("mode", "local") == "local":
            result = run_local_shell(template, agent, message)
        elif host_cfg.get("mode") == "ssh_password":
            if store.vault is None:
                raise ValueError("Credential vault is unavailable")
            creds = store.vault.get(host_identity(host_cfg))
            if not creds:
                raise ValueError("Credentials are missing for this host")
            result = run_remote_shell_password(host_cfg, creds, template, agent, message)
        else:
            result = run_remote_shell(host_cfg, template, agent, message)
    else:
        raise ValueError("This host does not define send_mode=stdin or send_command_template")
    return {"agent_id": agent_id, "message": message, **result}


def find_codex_session_by_probe(
    config: dict[str, Any],
    host_cfg: dict[str, Any],
    token: str,
    since_ts: float,
) -> dict[str, Any] | None:
    base_paths = config.get("paths", {})
    host_paths = {**base_paths, **host_cfg.get("paths", {})}
    root = host_paths.get("codex_sessions")
    deadline = utc_now_ts() + int(config.get("probe_timeout_sec", 20))
    while utc_now_ts() <= deadline:
        matches: list[dict[str, Any]] = []
        for path in get_recent_files(root, "*.jsonl", config.get("session_scan_limit", 120), True):
            try:
                if path.stat().st_mtime < since_ts - 5:
                    continue
                raw = path.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if token not in raw:
                continue
            session = parse_codex_session(path)
            if session and session.get("session_id"):
                matches.append(session)
        if matches:
            matches.sort(key=lambda s: s.get("heartbeat_ts") or 0, reverse=True)
            return matches[0]
        time.sleep(0.5)
    return None


def probe_agent_session(store: SnapshotStore, agent_id: str) -> dict[str, Any]:
    agent, host_cfg = store.find_agent(agent_id)
    if not agent or not host_cfg:
        raise ValueError("Agent not found")
    if host_cfg.get("mode", "local") != "local":
        raise ValueError("Session probe is only supported for local hosts")
    if agent.get("agent_type") != "codex":
        raise ValueError("Session probe is only supported for Codex agents")
    if not agent.get("cmux_workspace_id") or not agent.get("cmux_surface_id"):
        raise ValueError("Session probe requires CMUX workspace and surface ids")

    token = f"AF-PROBE-{secrets.token_hex(3).upper()}"
    template = str(store.config.get("probe_message_template") or "请只回复：{token}")
    message = template.format(token=token)
    since_ts = utc_now_ts()
    send_result = send_agent_action(store, agent_id, message)
    if send_result.get("returncode") != 0:
        return {"ok": False, "token": token, "send_result": send_result, "error": send_result.get("stderr") or "probe send failed"}

    session = find_codex_session_by_probe(store.config, host_cfg, token, since_ts)
    if not session:
        return {"ok": False, "token": token, "send_result": send_result, "error": "probe token was not found in recent Codex session files"}

    binding = write_session_binding(store.config, agent, str(session["session_id"]), token)
    store.refresh()
    return {
        "ok": True,
        "token": token,
        "send_result": send_result,
        "session_id": session["session_id"],
        "binding": binding,
    }


class DashboardHandler(BaseHTTPRequestHandler):
    store: SnapshotStore | None = None

    def _send_json(self, payload: Any, status: int = 200) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _serve_static(self, path: str) -> None:
        target = STATIC_DIR / path.lstrip("/")
        if target.is_dir():
            target = target / "index.html"
        if not target.exists() or not target.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        ctype = "text/plain; charset=utf-8"
        if target.suffix == ".html":
            ctype = "text/html; charset=utf-8"
        elif target.suffix == ".js":
            ctype = "application/javascript; charset=utf-8"
        elif target.suffix == ".css":
            ctype = "text/css; charset=utf-8"
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/api/snapshot":
            assert self.store is not None
            self._send_json(self.store.get())
            return
        if parsed.path == "/api/hosts":
            assert self.store is not None
            host_store = ManagedHostStore(self.store.config, self.store.vault) if self.store.vault else None
            self._send_json({"ok": True, "hosts": host_store.list_hosts(self.store.snapshot) if host_store else []})
            return
        if parsed.path == "/api/refresh":
            assert self.store is not None
            threading.Thread(target=self.store.refresh, daemon=True).start()
            self._send_json({"ok": True})
            return
        if parsed.path == "/api/focus":
            # Focus window by PID
            params = parse_qs(parsed.query)
            pid = int(params.get("pid", [0])[0]) if params.get("pid") else 0
            
            if pid <= 0:
                result = {"success": False, "error": "Invalid PID"}
            else:
                result = focus_window_by_pid(pid)
            
            self._send_json(result)
            return
        if parsed.path in {"/", "/index.html"}:
            self._serve_static("index.html")
            return
        if parsed.path.startswith("/static/"):
            self._serve_static(parsed.path.replace("/static/", "", 1))
            return
        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        data = safe_json_loads(raw.decode("utf-8", "ignore")) or {}
        assert self.store is not None

        if parsed.path == "/api/rename":
            rename_key = str(data.get("rename_key", "")).strip()
            alias = str(data.get("alias", "")).strip()
            if not rename_key:
                self._send_json({"ok": False, "error": "rename_key required"}, 400)
                return
            aliases = set_alias(self.store.config, rename_key, alias or None)
            self.store.refresh()
            self._send_json({"ok": True, "aliases_count": len(aliases)})
            return

        if parsed.path == "/api/action":
            agent_id = str(data.get("agent_id", "")).strip()
            message = str(data.get("message", "")).strip()
            if not agent_id or not message:
                self._send_json({"ok": False, "error": "agent_id and message required"}, 400)
                return
            try:
                result = send_agent_action(self.store, agent_id, message)
                self._send_json({"ok": result["returncode"] == 0, "result": result})
            except Exception as exc:
                self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 400)
            return

        if parsed.path == "/api/probe-session":
            agent_id = str(data.get("agent_id", "")).strip()
            if not agent_id:
                self._send_json({"ok": False, "error": "agent_id required"}, 400)
                return
            try:
                result = probe_agent_session(self.store, agent_id)
                self._send_json(result, 200 if result.get("ok") else 400)
            except Exception as exc:
                self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 400)
            return

        if parsed.path == "/api/hosts/save":
            try:
                host_store = ManagedHostStore(self.store.config, self.store.vault)
                host = host_store.save_host(data)
                self.store.refresh()
                self._send_json({"ok": True, "host": host})
            except Exception as exc:
                self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 400)
            return

        if parsed.path == "/api/hosts/delete":
            host_id = str(data.get("id", "")).strip()
            if not host_id:
                self._send_json({"ok": False, "error": "id required"}, 400)
                return
            try:
                host_store = ManagedHostStore(self.store.config, self.store.vault)
                host_store.delete_host(host_id)
                self.store.refresh()
                self._send_json({"ok": True})
            except Exception as exc:
                self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 400)
            return

        if parsed.path == "/api/hosts/toggle":
            host_id = str(data.get("id", "")).strip()
            if not host_id:
                self._send_json({"ok": False, "error": "id required"}, 400)
                return
            try:
                if self.store.vault is None:
                    raise ValueError("Credential vault is unavailable")
                host_store = ManagedHostStore(self.store.config, self.store.vault)
                host = host_store.toggle_host(host_id, bool(data.get("enabled")))
                self.store.refresh()
                self._send_json({"ok": True, "host": host})
            except Exception as exc:
                self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 400)
            return

        if parsed.path == "/api/hosts/test":
            try:
                host_store = ManagedHostStore(self.store.config, self.store.vault)
                draft = host_store.build_draft(data)
                result = test_managed_host_connection(draft, self.store.config)
                self._send_json({"ok": result.get("ok", False), "result": result}, 200 if result.get("ok") else 400)
            except Exception as exc:
                self._send_json({"ok": False, "error": f"{type(exc).__name__}: {exc}"}, 400)
            return

        self.send_error(HTTPStatus.NOT_FOUND)

    def log_message(self, fmt: str, *args: Any) -> None:
        return


def load_config(path: str | None) -> dict[str, Any]:
    config_path = Path(path) if path else (BASE_DIR / "config.json")
    config_dir = config_path.parent
    config = json.loads(json.dumps(DEFAULT_CONFIG))
    if config_path.exists():
        user = json.loads(config_path.read_text(encoding="utf-8"))
        config.update({k: v for k, v in user.items() if k not in {"paths", "status", "hosts"}})
        if "paths" in user:
            config["paths"].update(user["paths"])
        if "status" in user:
            config["status"].update(user["status"])
        if "hosts" in user:
            config["hosts"] = user["hosts"]
        if "managed_hosts" in user:
            config["managed_hosts"] = user["managed_hosts"]
    config["aliases_file"] = resolve_relative_path(config_dir, config.get("aliases_file")) or str(BASE_DIR / "session_aliases.json")
    config["session_bindings_file"] = resolve_relative_path(config_dir, config.get("session_bindings_file")) or str(BASE_DIR / "session_bindings.json")
    config["credentials_file"] = resolve_relative_path(config_dir, config.get("credentials_file")) or str(BASE_DIR / "credentials.enc.json")
    config["_config_path"] = str(config_path)
    config["_credentials_path"] = str(Path(config["credentials_file"]))
    return config


def run_server(config: dict[str, Any], host: str, port: int, vault: CredentialVault | None = None) -> None:
    store = SnapshotStore(config, vault)
    DashboardHandler.store = store
    threading.Thread(target=store.refresh, daemon=True).start()

    def loop() -> None:
        while True:
            time.sleep(max(2, int(config.get("refresh_interval_sec", 10))))
            store.refresh()

    threading.Thread(target=loop, daemon=True).start()
    httpd = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"Agent Foreman dashboard: http://{host}:{port}")
    httpd.serve_forever()


def main() -> None:
    parser = argparse.ArgumentParser(description="Browser dashboard for local and remote Codex / Claude Code agents")
    parser.add_argument("--config", help="Path to JSON config file")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--probe", help="Base64-encoded JSON payload for remote probe")
    args = parser.parse_args()

    if args.probe:
        payload = json.loads(base64.b64decode(args.probe).decode("utf-8"))
        config = payload["config"]
        host_cfg = payload["host"]
        result = summarize_host(config, host_cfg)
        sys.stdout.write(json.dumps(result, ensure_ascii=False))
        return

    config = load_config(args.config)
    # Only initialize vault if there are managed hosts
    if config.get("managed_hosts"):
        vault = bootstrap_vault(config)
    else:
        vault = None
    run_server(config, args.host, args.port, vault)


if __name__ == "__main__":
    main()
