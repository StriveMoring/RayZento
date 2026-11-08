#!/usr/bin/env python3
"""Provision standalone RayZento VPS services."""
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import ssl
import tempfile
import time
from urllib.parse import quote, urlencode
import uuid

import rayzento_core as vps

F = vps.Failure
NAMES = {
    "vless-reality": ("xray", "VLESS TCP REALITY Vision", ("tcp",)),
    "xhttp-reality": ("xray", "VLESS XHTTP REALITY 加密", ("tcp",)),
    "xhttp-encrypted": ("xray", "VLESS XHTTP 加密", ("tcp",)),
    "ws-encrypted": ("xray", "VLESS WS 加密", ("tcp",)),
    "xhttp-h3": ("xray", "VLESS XHTTP TLS H3", ("udp",)),
    "xhttp-h2": ("xray", "VLESS XHTTP TLS H2", ("tcp",)),
    "tuic": ("sing-box", "TUIC v5", ("udp",)),
    "naive": ("sing-box", "NaiveProxy", ("tcp", "udp")),
    "anytls": ("sing-box", "AnyTLS", ("tcp",)),
    "anytls-reality": ("sing-box", "AnyTLS REALITY", ("tcp",)),
    "mihomo-reality": ("mihomo", "Mihomo VLESS TCP REALITY Vision（可选）", ("tcp",)),
}
TLS = {"xhttp-h3", "xhttp-h2", "tuic", "naive", "anytls"}
REALITY = {"vless-reality", "xhttp-reality", "anytls-reality", "mihomo-reality"}
HOST = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
PRIVATE = ["0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
           "172.16.0.0/12", "192.168.0.0/16", "198.18.0.0/15", "224.0.0.0/3"]
VIS = "xtls-rprx-vision"
PRESETS = {
    "standard": ("vless-reality", "tuic", "anytls"),
    "full": tuple(k for k in NAMES if k != "mihomo-reality"),
}


def port_plan(preset, requested, used):
    used = set(used)
    choices = dict.fromkeys(PRESETS.get(preset, ()), "auto")
    explicit = set()
    for item in requested:
        name, sep, port = item.partition("=")
        if name not in NAMES or name in explicit:
            raise F(f"未知或重复的协议：{name}。用 profiles 查看协议名称。")
        explicit.add(name)
        choices[name] = port if sep else "auto"
    if not choices:
        raise F("请指定 --preset 或 --profile，例如 --profile vless-reality。")
    selected = {}
    for k, raw in choices.items():
        if raw != "auto":
            if not raw.isascii() or not raw.isdecimal() or len(raw) > 5 or not 1024 <= int(raw) <= 65535:
                raise F(f"{k} 需要 auto 或 1024–65535 数字端口。")
            port = int(raw)
            if port in used:
                raise F(f"{k} 端口 {port} 已被占用或重复。")
            used.add(port)
            selected[k] = port
    free = sorted(set(range(20000, 60000)) - used)
    for k, raw in choices.items():
        if raw == "auto":
            if not free:
                raise F("自动端口范围没有空闲端口。")
            selected[k] = free.pop(secrets.randbelow(len(free)))
    return {k: selected[k] for k in choices}


def listening_ports():
    out = vps.command(["ss", "-H", "-lntu"]).stdout.decode(errors="replace")
    return {int(z[4].rsplit(":", 1)[1]) for l in out.splitlines()
            if len(z := l.split()) >= 5 and z[4].rsplit(":", 1)[-1].isdecimal() and ":" in z[4]}


def require_unused(cores):
    for c in cores:
        unit = vps.SPECS[c][1]
        if (vps.OPT / c).exists() or (vps.UNITS / unit).is_symlink() or vps.sysprop(unit, "LoadState") != "not-found":
            raise F(f"{unit} 或安装目录已经存在。请用 audit 查看已安装核心。")


def tls_check(cert, key, sni):
    for p in (cert, key):
        vps.root_owned_path(p)
        if not p.is_file():
            raise F("TLS 证书和私钥必须是已有普通文件。")
    if key.stat().st_mode & 0o007:
        raise F("TLS 私钥不可允许其他用户读取。")
    # Only load the key on this VPS. An encrypted key would require interaction.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(cert), str(key), password=lambda: "")
    try:
        ipaddress.IPv4Address(sni)
        flag = "-checkip"
    except ValueError:
        flag = "-checkhost"
    r = vps.command(["openssl", "x509", "-in", cert, "-noout", flag, sni])
    if b"does match certificate" not in r.stdout:
        raise F("TLS 证书不匹配 --sni。")
    vps.command(["openssl", "x509", "-in", cert, "-noout", "-checkend", "86400"])


def reality_key(core, exe):
    args = ["x25519"] if core == "xray" else ["generate", "reality-keypair"]
    text = vps.command([exe, *args]).stdout.decode()
    fields = dict(re.findall(r"(?m)^([^:\n]+):[ \t]*(\S+)", text))
    pri = fields.get("PrivateKey", "")
    pub = fields.get("Password (PublicKey)", fields.get("PublicKey", ""))
    if any(not re.fullmatch(r"[A-Za-z0-9_-]{43}", x) for x in (pri, pub)):
        raise F("核心 REALITY 密钥输出格式变化，请人工核对。")
    return pri, pub, secrets.token_hex(8)


def vless_keys(exe):
    text = vps.command([exe, "vlessenc"]).stdout.decode()
    keys = [re.findall(rf'"{name}"\s*:\s*"([^"]+)"', text) for name in ("decryption", "encryption")]
    if any(len(k) != 2 for k in keys) or len(keys[1][-1].split(".")[-1]) != 1579:
        raise F("新版 Xray 的 VLESS 密钥输出格式变化，请人工核对。")
    return keys[0][-1], keys[1][-1]


def profiles(ports, server, sni, cover, bind, cert, key, binaries, generate_reality=reality_key, generate_vless=vless_keys):
    configs, clients, links = {}, [], []
    xray, sing, meta = [], [], []
    ex_real = generate_reality("xray", binaries["xray"]) if {"vless-reality", "xhttp-reality"} & ports.keys() else None
    encryption = generate_vless(binaries["xray"]) if {"xhttp-reality", "xhttp-encrypted", "ws-encrypted"} & ports.keys() else (None, None)
    for k, port in ports.items():
        core, title, transport = NAMES[k]
        user = str(uuid.uuid4())
        pw = secrets.token_urlsafe(24)
        n = {"name": title, "type": "vless", "server": server, "port": port, "uuid": user, "udp": True, "packet-encoding": "xudp"}
        if core == "xray":
            net = "tcp" if k == "vless-reality" else "ws" if k == "ws-encrypted" else "xhttp"
            security = "reality" if k in REALITY else "tls" if k in TLS else "none"
            st = {"network": net, "security": security}
            h = {"id": user}
            n.update(network=net, tls=security != "none")
            u = {"type": net, "security": security, "encryption": "none"}
            if k in {"vless-reality", "xhttp-reality", "xhttp-encrypted", "ws-encrypted"}:
                n["flow"] = u["flow"] = h["flow"] = VIS
            d = "none"
            if k in {"xhttp-reality", "xhttp-encrypted", "ws-encrypted"}:
                d, n["encryption"] = encryption
                u["encryption"] = n["encryption"]
            if security == "reality":
                pri, pub, sid = ex_real
                st["realitySettings"] = {"target": cover + ":443", "serverNames": [cover], "privateKey": pri, "shortIds": [sid]}
                n.update(servername=cover, **{"client-fingerprint": "chrome", "reality-opts": {"public-key": pub, "short-id": sid, "support-x25519mlkem768": True}})
                u.update(sni=cover, fp="chrome", pbk=pub, sid=sid)
            if security == "tls":
                alpn = ["h3"] if k == "xhttp-h3" else ["h2"]
                st["tlsSettings"] = {"alpn": alpn, "certificates": [{"certificateFile": str(cert), "keyFile": str(key)}]}
                n.update(servername=sni, alpn=alpn, **{"client-fingerprint": "chrome"})
                u.update(sni=sni, fp="chrome", alpn=",".join(alpn))
            if net in {"xhttp", "ws"}:
                path = "/" + secrets.token_hex(12)
                st["xhttpSettings" if net == "xhttp" else "wsSettings"] = {"path": path, **({"mode": "auto"} if net == "xhttp" else {})}
                n["xhttp-opts" if net == "xhttp" else "ws-opts"] = dict(st["xhttpSettings" if net == "xhttp" else "wsSettings"])
                u["path"] = path
                if net == "xhttp":
                    u["mode"] = "auto"
            xray.append({"tag": k, "listen": bind, "port": port, "protocol": "vless",
                         "settings": {"clients": [h], "decryption": d}, "streamSettings": st})
            links.append("vless://" + user + "@" + server + ":" + str(port) + "?" + urlencode(u) + "#" + quote(title))
            clients.append(n)
        elif core == "sing-box":
            protocol = "tuic" if k == "tuic" else "naive" if k == "naive" else "anytls"
            tls = {"enabled": True, "certificate_path": str(cert), "key_path": str(key)}
            auth = {"password": pw}
            entry = {"type": protocol, "tag": k, "listen": bind, "listen_port": port, "users": [auth], "tls": tls}
            n = {"name": title, "type": protocol, "server": server, "port": port, "password": pw, "udp": protocol != "naive", "sni": sni}
            if protocol == "tuic":
                auth["uuid"] = n["uuid"] = user
                tls["alpn"] = n["alpn"] = ["h3"]
                entry["congestion_control"] = n["congestion-controller"] = "bbr"
            if protocol == "naive":
                auth["username"] = n["username"] = "rz-" + secrets.token_hex(4)
                n["client"] = "sing-box/Naive；不是 Xray VLESS，也不导入 Mihomo"
            if k == "anytls-reality":
                pri, pub, sid = generate_reality(core, binaries[core])
                entry["tls"] = {"enabled": True, "server_name": cover, "reality": {"enabled": True,
                              "handshake": {"server": cover, "server_port": 443}, "private_key": pri, "short_id": [sid]}}
                n["sni"] = cover
                n["client-fingerprint"] = "chrome"
                n["reality-opts"] = {"public-key": pub, "short-id": sid}
            sing.append(entry)
            clients.append(n)
        else:
            pri, pub, sid = generate_reality(core, binaries[core])
            meta.append({"name": k, "type": "vless", "listen": bind, "port": port,
                         "users": [{"username": "rayzento", "uuid": user, "flow": VIS}],
                         "reality-config": {"dest": cover + ":443", "private-key": pri, "short-id": [sid], "server-names": [cover]}})
            n.update(network="tcp", tls=True, flow=VIS, servername=cover, **{"client-fingerprint": "chrome", "reality-opts": {"public-key": pub, "short-id": sid}})
            clients.append(n)
            u = {"type": "tcp", "security": "reality", "sni": cover, "fp": "chrome", "pbk": pub, "sid": sid, "encryption": "none", "flow": VIS}
            links.append("vless://" + user + "@" + server + ":" + str(port) + "?" + urlencode(u) + "#" + quote(title))
    if xray:
        configs["xray"] = {"log": {"loglevel": "warning"}, "inbounds": xray,
            "outbounds": [{"protocol": "freedom", "settings": {
                "domainStrategy": "ForceIPv4",
                "finalRules": [{"action": "block", "ip": PRIVATE + ["::/0"], "blockDelay": "0-0"}]}}]}
    if sing:
        configs["sing-box"] = {"log": {"level": "warn"}, "inbounds": sing,
            "dns": {"servers": [{"type": "udp", "tag": "ipv4-dns", "server": "1.1.1.1"}], "final": "ipv4-dns", "strategy": "ipv4_only"},
            "outbounds": [{"type": "direct", "tag": "internet"}],
            "route": {"default_domain_resolver": "ipv4-dns", "rules": [
                {"action": "resolve", "strategy": "ipv4_only"},
                {"ip_is_private": True, "action": "reject"},
                {"ip_cidr": PRIVATE + ["::/0"], "action": "reject"}], "final": "internet"}}
    if meta:
        configs["mihomo"] = {"ipv6": False, "mode": "rule", "log-level": "warning",
            "tun": {"enable": False}, "dns": {"enable": False}, "listeners": meta,
            "rules": [*[f"IP-CIDR,{p},REJECT" for p in PRIVATE], "IP-CIDR6,::/0,REJECT,no-resolve", "MATCH,DIRECT"]}
    return configs, clients, links


def unit_text(core, target, config):
    cmd = " ".join(map(str, vps.core_command(core, target, config)))
    return f"""[Unit]
Description=RayZento {core}
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
ExecStart={cmd}
NoNewPrivileges=yes
CapabilityBoundingSet=
UMask=0077
Restart=on-failure
RestartSec=3
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
"""


def install(args):
    import rayzento_nodes as node_export

    ports = port_plan(args.preset, args.profile, listening_ports())
    cores = list(dict.fromkeys(NAMES[k][0] for k in ports))
    if any(getattr(args, core) for core in vps.SPECS if core not in cores):
        raise F("只能给选中协议所需的核心指定版本。")
    if not HOST.fullmatch(args.server) or not HOST.fullmatch(args.cover) or not HOST.fullmatch(args.sni or args.server):
        raise F("server / sni / cover 需要域名或 IPv4 地址。")
    bind = str(ipaddress.IPv4Address(args.bind))
    sni = args.sni or args.server
    cert = key = None
    if TLS & ports.keys():
        if not args.certificate or not args.key:
            raise F("选中的 TLS 协议需要有效证书和私钥，请指定 --certificate 和 --key。")
        cert, key = (Path(p).resolve(strict=True) for p in (args.certificate, args.key))
        tls_check(cert, key, sni)
    if not args.prepare_only and REALITY & ports.keys() and not args.reality_client_ready:
        raise F("请先核对 REALITY 客户端，再用 --reality-client-ready 确认。")
    with vps.lock():
        require_unused(cores)
        stage = Path(tempfile.mkdtemp(prefix="fresh-", dir=vps.ROOT))
        targets, cfgs, origins = {}, {}, {}
        for core in cores:
            release = vps.release(core, getattr(args, core))
            tag = vps.version(release["tag_name"])
            blob, digest = vps.binary_from_archive(core, release, vps.arch())
            d = stage / core
            d.mkdir(mode=0o700)
            targets[core], cfgs[core] = d / core, d / "server.json"
            targets[core].write_bytes(blob)
            targets[core].chmod(0o755)
            if vps.parse_banner(core, vps.version_banner(targets[core])) != tag:
                raise F("候选核心版本不符。")
            origins[core] = vps.release_record(core, tag, digest, vps.sha(targets[core]))
            print(f"{core} {tag} {digest}")
        configs, clients, links = profiles(ports, args.server, sni, args.cover, bind, cert, key, targets)
        inventory = node_export.records(ports, clients, links)
        for core in cores:
            vps.atomic_json(cfgs[core], configs[core])
            vps.atomic_json(stage / core / "nodes.json",
                            [n for n in inventory if NAMES[n["profile"]][0] == core])
            vps.command(vps.config_check(core, targets[core], cfgs[core]), timeout=35)
        vps.atomic_json(stage / "client-profiles.json", {"mihomo": [n for n in clients if n["type"] != "naive"], "all": clients})
        (stage / "v2rayn-vless.txt").write_text("\n".join(links) + "\n")
        vps.atomic_json(stage / "provision.json", {
            "ports": ports, "bind": bind, "certificate": str(cert) if cert else None,
            "key": str(key) if key else None, "sni": sni,
            "origins": origins, "configs": {c: vps.sha(cfgs[c]) for c in cores},
        })
        print(f"私有候选目录：{stage}")
        for k, port in ports.items():
            print(f"{k}: {port}/{'+'.join(NAMES[k][2])} {NAMES[k][1]}")
        if args.prepare_only:
            print(f"候选已校验。运行 sudo rayzento activate {stage.name} 启用。如含 REALITY，加 --reality-client-ready。")
            return
        activate(stage, args.reality_client_ready)


def activate(stage, reality_ready):
    vps.root_owned_path(stage)
    data = json.loads((stage / "provision.json").read_text())
    ports = data["ports"]
    bind = str(ipaddress.IPv4Address(data["bind"]))
    cores = list(dict.fromkeys(NAMES[k][0] for k in ports))
    if REALITY & ports.keys() and not reality_ready:
        raise F("请先核对 REALITY 客户端，再用 --reality-client-ready 确认。")
    targets, cfgs = {}, {}
    for core in cores:
        targets[core], cfgs[core] = stage / core / core, stage / core / "server.json"
        if vps.sha(targets[core]) != data["origins"][core]["binary_sha256"] or vps.sha(cfgs[core]) != data["configs"][core]:
            raise F("候选目录与预检时的指纹不一致。")
        vps.command(vps.config_check(core, targets[core], cfgs[core]), timeout=35)
    if data.get("certificate"):
        tls_check(Path(data["certificate"]), Path(data["key"]), data["sni"])
    # Recheck under the upgrade lock immediately before activating public listeners.
    require_unused(cores)
    if set(ports.values()) & listening_ports():
        raise F("候选端口已被占用。")
    if vps.OPT.is_symlink():
        raise F("拒绝符号链接安装目录。")
    vps.OPT.mkdir(mode=0o700, exist_ok=True)
    vps.root_owned_path(vps.OPT)
    installed, created = [], []
    try:
        for core in cores:
            target_dir = vps.OPT / core
            target_dir.mkdir(mode=0o700)
            created.append(target_dir)
            target = target_dir / core
            config = target_dir / "server.json"
            shutil.copy2(targets[core], target)
            shutil.copy2(cfgs[core], config)
            shutil.copy2(stage / core / "nodes.json", target_dir / "nodes.json")
            vps.atomic_json(target_dir / "origin.json", data["origins"][core])
            unit = vps.SPECS[core][1]
            dest = vps.UNITS / unit
            with dest.open("x") as f:
                f.write(unit_text(core, target, config))
            installed.append(dest)
            dest.chmod(0o644)
        vps.command(["systemctl", "daemon-reload"])
        for core in cores:
            unit = vps.SPECS[core][1]
            target = vps.OPT / core / core
            expected = [f"{protocol} {bind}:{port}" for k, port in ports.items() if NAMES[k][0] == core for protocol in NAMES[k][2]]
            # Linux ss may show '*' instead of 0.0.0.0; use exact port/protocol after start.
            vps.command(["systemctl", "start", unit], timeout=40)
            want = {x.split()[0] + " " + x.rsplit(":", 1)[-1] for x in expected}
            expected_sha = vps.sha(target)
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                pid = int(vps.sysprop(unit, "MainPID") or 0)
                now = {x.split()[0] + " " + x.rsplit(":", 1)[-1] for x in vps.listeners(pid)} if pid > 1 else set()
                if want <= now and vps.running_match(unit, target, [], expected_sha):
                    break
                time.sleep(0.5)
            else:
                raise F(f"{unit} 未提供预期 TCP/UDP 监听。")
        vps.command(["systemctl", "enable", *[x.name for x in installed]])
        print("服务已启动且监听就绪。防火墙没有自动开放；请核对需要开放的端口并从客户端验收。")
    except BaseException:
        blocked = set()
        for dest in reversed(installed):
            try:
                vps.command(["systemctl", "disable", "--now", dest.name], timeout=35)
                dest.unlink(missing_ok=True)
            except (F, OSError):
                blocked.add(dest.name)
        for d in reversed(created):
            if vps.SPECS[d.name][1] not in blocked:
                shutil.rmtree(d)
        vps.command(["systemctl", "daemon-reload"])
        if blocked:
            raise F("初始化失败，以下单元未能自动清理，已保留对应文件：" + ", ".join(sorted(blocked)))
        raise
    # Export failures must not undo an otherwise healthy installation.
    import rayzento_nodes as node_export
    inventory = [n for core in vps.ORDER if (vps.OPT / core / "nodes.json").is_file()
                 for n in node_export.load(core)]
    try:
        node_export.export(inventory, locked=True)
        node_export.display(inventory)
    except (F, OSError, ValueError) as error:
        print(f"服务已启动，导出尚需处理：{error}。可在节点菜单重新导出。")


def add_install_options(parser):
    parser.add_argument("--server", required=True, help="客户端连接的 VPS IPv4 或域名")
    parser.add_argument("--preset", choices=tuple(PRESETS))
    parser.add_argument("--profile", action="append", default=[], metavar="NAME[=PORT]",
                        help="启用单个协议，可多次指定；省略端口则自动分配")
    parser.add_argument("--bind", default="0.0.0.0")
    parser.add_argument("--sni")
    parser.add_argument("--cover", default="apple.com")
    parser.add_argument("--certificate")
    parser.add_argument("--key")
    for core in vps.SPECS:
        parser.add_argument(f"--{core}-version", dest=core, type=vps.version)
    parser.add_argument("--prepare-only", action="store_true", help="生成候选并校验，暂不启动")
    parser.add_argument("--reality-client-ready", action="store_true")
