"""On-demand, redacted REALITY diagnostics; no service or configuration changes."""
import datetime
import ipaddress
import json
import re
import socket
import ssl
from urllib.parse import urlsplit

import rayzento_core as vps

SENSITIVE = {"id", "uuid", "username", "password", "token", "secret", "privatekey", "publickey", "shortid", "shortids", "decryption", "encryption"}


def secret_values(data):
    found = []
    if isinstance(data, dict):
        for key, value in data.items():
            if re.sub(r"[^a-z]", "", key.lower()) in SENSITIVE:
                values = value if isinstance(value, list) else [value]
                found.extend(item for item in values if isinstance(item, str) and len(item) >= 6)
            found.extend(secret_values(value))
    elif isinstance(data, list):
        for item in data:
            found.extend(secret_values(item))
    return found


def redact(text, secrets):
    for value in sorted(set(secrets), key=len, reverse=True):
        text = text.replace(value, "[redacted]")
    text = re.sub(r"\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b", "[uuid]", text)
    text = re.sub(r"[A-Za-z0-9_+/=-]{40,}", "[key]", text)
    text = re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://)[^\s/@]+@", r"\1[credentials]@", text)
    return text


def tls_probe(address, port, sni):
    context = ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    try:
        with socket.create_connection((address, port), timeout=4) as connection:
            connection.settimeout(5)
            with context.wrap_socket(connection, server_hostname=sni) as tls:
                return {"ok": True, "tls": tls.version(), "alpn": tls.selected_alpn_protocol()}
    except (OSError, ValueError) as error:
        return {"ok": False, "error": type(error).__name__, "detail": str(error)[:240]}


def entries(core, config):
    for item in config.get("listeners" if core == "mihomo" else "inbounds", []):
        if core == "xray":
            stream = item.get("streamSettings", {})
            if stream.get("security") != "reality":
                continue
            reality = stream.get("realitySettings", {})
            target = reality.get("target", reality.get("dest", ""))
            names = reality.get("serverNames", [])
        elif core == "sing-box":
            tls = item.get("tls", {})
            reality = tls.get("reality", {})
            if not reality.get("enabled"):
                continue
            handshake = reality.get("handshake", {})
            target = str(handshake.get("server", "")) + ":" + str(handshake.get("server_port", 443))
            names = [tls.get("server_name", handshake.get("server", ""))]
        else:
            reality = item.get("reality-config", {})
            if not reality:
                continue
            target = reality.get("dest", "")
            names = reality.get("server-names", [])
        if not isinstance(target, str) or not isinstance(names, list) or not names or not isinstance(names[0], str):
            raise vps.Failure("REALITY 目标/SNI 配置格式无法识别。")
        parsed = urlsplit("//" + target)
        port = item.get("listen_port" if core == "sing-box" else "port")
        if not parsed.hostname or not isinstance(port, int) or not 1 <= port <= 65535:
            raise vps.Failure("REALITY 监听端口或目标格式无效。")
        yield {"profile": item.get("tag", item.get("name", "reality")), "listen": item.get("listen", "0.0.0.0"),
               "port": port, "target": parsed.hostname, "target_port": parsed.port or 443, "sni": names[0]}


def reality():
    report = {"utc": datetime.datetime.now(datetime.timezone.utc).isoformat(), "read_only": True, "cores": []}
    configs, secrets = {}, []
    for core in vps.ORDER:
        path = vps.OPT / core / "server.json"
        if not path.exists():
            continue
        if path.is_symlink():
            raise vps.Failure("拒绝读取符号链接服务配置。")
        vps.root_owned_path(path)
        configs[core] = json.loads(path.read_text())
        secrets.extend(secret_values(configs[core]))
    probes = {}
    for core, config in configs.items():
        targets = list(entries(core, config))
        if not targets:
            continue
        unit = vps.SPECS[core][1]
        row = {"core": core, "active": vps.sysprop(unit, "ActiveState"), "nodes": []}
        for entry in targets:
            key = (entry["target"], entry["target_port"], entry["sni"])
            if key not in probes:
                try:
                    records = socket.getaddrinfo(key[0], key[1], type=socket.SOCK_STREAM)
                    addresses = sorted({record[4][0] for record in records})
                    public_v4 = [address for address in addresses if ipaddress.ip_address(address).version == 4
                                 and ipaddress.ip_address(address).is_global]
                    probes[key] = {"resolved": addresses, "ipv4_tls": tls_probe(public_v4[0], key[1], key[2])
                                   if public_v4 else {"ok": False, "error": "NoPublicIPv4"}}
                except (OSError, ValueError) as error:
                    probes[key] = {"ok": False, "error": type(error).__name__, "detail": str(error)[:240]}
            listener = "127.0.0.1" if entry["listen"] == "0.0.0.0" else entry["listen"]
            address = ipaddress.ip_address(listener)
            local = tls_probe(listener, entry["port"], entry["sni"]) if address.is_loopback else {"skipped": "listener is not loopback/wildcard"}
            row["nodes"].append({**entry, "target_check": probes[key], "local_normal_tls_fallback": local})
        logs = vps.command(["journalctl", "-u", unit, "-n", "100", "--no-pager", "-o", "short-iso"], check=False)
        relevant = [line for line in logs.stdout.decode(errors="replace").splitlines()
                    if re.search(r"error|fail|reject|reality|tls|handshake|timeout", line, re.I)]
        row["recent_errors"] = [redact(line, secrets)[:400] for line in relevant[-16:]]
        report["cores"].append(row)
    print(json.dumps(report, ensure_ascii=False, indent=2))
