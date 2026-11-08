"""Own only RayZento's IPv4 ingress exceptions; never enable or flush a firewall."""
import fcntl
import ipaddress
import json
import re
import shlex
import shutil

import rayzento_core as vps

MARK = "rayzento-managed"
CHAIN = "RAYZENTO"
HOOK_TEXT = """# Managed by RayZento
[Unit]
After=nftables.service ufw.service firewalld.service netfilter-persistent.service
[Service]
ExecStartPre=+/usr/local/bin/rayzento firewall sync --runtime-only
"""


def run(args, **kwargs):
    return vps.command(args, timeout=40, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}, **kwargs)


def desired_ports():
    from rayzento_provision import NAMES
    result = set()
    for core in vps.ORDER:
        path = vps.OPT / core / "server.json"
        if not path.exists():
            continue
        if path.is_symlink():
            raise vps.Failure("防火墙拒绝读取符号链接配置。")
        vps.root_owned_path(path)
        config = json.loads(path.read_text())
        for entry in config["listeners" if core == "mihomo" else "inbounds"]:
            profile = entry["name" if core == "mihomo" else "tag"]
            if profile not in NAMES or NAMES[profile][0] != core:
                raise vps.Failure("防火墙发现不属于本核心的节点。")
            if ipaddress.ip_address(entry.get("listen", "0.0.0.0")).is_loopback:
                continue
            port = entry["listen_port" if core == "sing-box" else "port"]
            if type(port) is not int or not 1024 <= port <= 65535:
                raise vps.Failure("受管节点端口无效。")
            result.update((proto, port) for proto in NAMES[profile][2])
    if any((vps.ROOT / "certificates").glob("rz-*.json")):
        result.add(("tcp", 80))
    return result


def detect():
    ufw = shutil.which("ufw") and "Status: active" in run(["ufw", "status"], check=False).stdout.decode()
    firewalld = shutil.which("firewall-cmd") and run(["firewall-cmd", "--state"], check=False).returncode == 0
    if ufw and firewalld:
        raise vps.Failure("UFW 与 firewalld 同时启用，未擅自改动混合防火墙。")
    if ufw:
        return "ufw", None
    if firewalld:
        return "firewalld", None
    nft = json.loads(run(["nft", "-j", "list", "ruleset"]).stdout) if shutil.which("nft") else {"nftables": []}
    inputs = [item["chain"] for item in nft["nftables"] if "chain" in item
              and item["chain"].get("hook") == "input" and item["chain"]["family"] in ("ip", "inet")]
    if shutil.which("iptables"):
        lines = run(["iptables", "-w", "-S", "INPUT"]).stdout.decode().splitlines()
        if lines != ["-P INPUT ACCEPT"]:
            if any((c["family"], c["table"], c["name"]) != ("ip", "filter", "INPUT") for c in inputs):
                raise vps.Failure("发现自定义 nftables 与 iptables 混合入站链，未覆盖其策略。")
            return "iptables", lines
    return ("nftables", nft) if inputs else ("none", None)


def ufw_owned(text):
    rows = []
    for line in text.splitlines():
        tag = re.search(r"# " + MARK + r":(tcp|udp):(\d+)\s*$", line)
        if tag:
            number = re.match(r"\[\s*(\d+)\]", line.strip())
            if not number:
                raise vps.Failure("UFW 受管规则编号无法识别。")
            rows.append((int(number[1]), (tag[1], int(tag[2]))))
    return rows


def apply_ufw(ports):
    text = run(["ufw", "status", "numbered"]).stdout.decode()
    owned = {key for _, key in ufw_owned(text)}
    for proto, port in sorted(ports - owned):
        # Preserve an administrator's pre-existing identical allow rule and comment.
        allowed = any("(v6)" not in line and re.search(
            rf"\b{port}/{proto}\s+ALLOW(?: IN)?\s+Anywhere(?:\s|$)", line) for line in text.splitlines())
        if not allowed:
            run(["ufw", "insert", "1", "allow", "in", "from", "0.0.0.0/0", "to", "any",
                 "port", str(port), "proto", proto, "comment", f"{MARK}:{proto}:{port}"])
    current = ufw_owned(run(["ufw", "status", "numbered"]).stdout.decode())
    for number, key in sorted(current, reverse=True):
        if key not in ports:
            run(["ufw", "--force", "delete", str(number)])


def apply_firewalld(ports):
    state = vps.ROOT / "firewalld-owned.json"
    if state.is_symlink():
        raise vps.Failure("防火墙记录是符号链接。")
    if state.exists():
        vps.root_owned_path(state)
    owned = json.loads(state.read_text()) if state.exists() else []
    if not isinstance(owned, list) or any(not isinstance(row, list) or len(row) != 3
                                        or type(row[2]) is not bool for row in owned):
        raise vps.Failure("防火墙归属记录无效。")
    for z, port, _ in owned:
        if not isinstance(z, str) or not isinstance(port, str) or not re.fullmatch(r"[A-Za-z0-9_-]+", z) or not re.fullmatch(r"\d+/(tcp|udp)", port):
            raise vps.Failure("防火墙归属记录无效。")
    routes = json.loads(run(["ip", "-j", "-4", "route", "show", "default"]).stdout)
    interface = min(routes, key=lambda item: item.get("metric", 0)).get("dev") if routes else None
    zone = run(["firewall-cmd", "--get-zone-of-interface=" + interface], check=False).stdout.decode().strip() if interface else ""
    if not zone or zone == "no zone":
        zone = run(["firewall-cmd", "--get-default-zone"]).stdout.decode().strip()
    if not re.fullmatch(r"[A-Za-z0-9_-]+", zone):
        raise vps.Failure("firewalld zone 无法识别。")
    wanted = [[zone, f"{port}/{proto}", permanent] for proto, port in sorted(ports) for permanent in (False, True)]
    for row in wanted:
        z, port, permanent = row
        base = ["firewall-cmd", "--zone=" + z] + (["--permanent"] if permanent else [])
        status = run([*base, "--query-port=" + port], check=False)
        if status.returncode not in (0, 1):
            raise vps.Failure("无法查询 firewalld 端口。")
        if status.returncode == 1:
            if row not in owned:
                owned.append(row)
                vps.atomic_json(state, owned)
            run([*base, "--add-port=" + port])
    for row in list(owned):
        if row not in wanted:
            z, port, permanent = row
            if not re.fullmatch(r"[A-Za-z0-9_-]+", z) or not re.fullmatch(r"\d+/(tcp|udp)", port):
                raise vps.Failure("防火墙归属记录无效。")
            base = ["firewall-cmd", "--zone=" + z] + (["--permanent"] if permanent else [])
            run([*base, "--remove-port=" + port])
            owned.remove(row)
            vps.atomic_json(state, owned)


def nft_plan(document, ports):
    commands = []
    chains = [x["chain"] for x in document["nftables"] if "chain" in x and x["chain"].get("hook") == "input"
              and x["chain"]["family"] in ("ip", "inet")]
    for item in document["nftables"]:
        rule = item.get("rule", {})
        if rule.get("comment") == MARK:
            if not any((c["family"], c["table"], c["name"]) ==
                       (rule["family"], rule["table"], rule["chain"]) for c in chains):
                raise vps.Failure("受管规则不在预期 INPUT 链。")
            commands.append(f'delete rule {rule["family"]} {json.dumps(rule["table"])} {json.dumps(rule["chain"])} handle {int(rule["handle"])}')
    for chain in chains:
        if chain.get("type") != "filter":
            raise vps.Failure("非标准 INPUT 链，未改动。")
        prefix = f'insert rule {chain["family"]} {json.dumps(chain["table"])} {json.dumps(chain["name"])} '
        if chain["family"] == "inet":
            prefix += "meta nfproto ipv4 "
        for proto in ("tcp", "udp"):
            numbers = sorted(port for protocol, port in ports if protocol == proto)
            if numbers:
                values = ", ".join(map(str, numbers))
                commands.append(prefix + f'{proto} dport {{ {values} }} counter accept comment "{MARK}"')
    return "\n".join(commands) + "\n" if commands else ""


def apply_nftables(document, ports):
    script = nft_plan(document, ports)
    if script:
        run(["nft", "-c", "-f", "-"], input=script.encode())
        run(["nft", "-f", "-"], input=script.encode())


def apply_iptables(lines, ports):
    if not shutil.which("iptables-restore"):
        raise vps.Failure("缺少 iptables-restore，未更改现有防火墙。")
    old = run(["iptables", "-w", "-S", CHAIN], check=False)
    jumps = [shlex.split(line)[2:] for line in lines if shlex.split(line)[-2:] == ["-j", CHAIN]]
    if any("--comment" not in rule or rule[rule.index("--comment") + 1] != MARK for rule in jumps):
        raise vps.Failure("同名 iptables 跳转不属于 RayZento，未改动。")
    if old.returncode == 0:
        rules = [shlex.split(line) for line in old.stdout.decode().splitlines() if line.startswith("-A ")]
        if not jumps or any("--comment" not in rule or rule[rule.index("--comment") + 1] != MARK for rule in rules + jumps):
            raise vps.Failure("同名 iptables 链不属于 RayZento，未改动。")
    elif old.returncode != 1:
        raise vps.Failure("无法读取 iptables 受管链。")
    if not ports and old.returncode == 1:
        return
    commands = ["*filter", f":{CHAIN} - [0:0]", f"-F {CHAIN}"]
    commands += ["-D INPUT " + shlex.join(rule) for rule in jumps]
    if ports:
        commands.append(f"-I INPUT 1 -m comment --comment {MARK} -j {CHAIN}")
        commands += [f"-A {CHAIN} -p {proto} --dport {port} -m comment --comment {MARK} -j ACCEPT" for proto, port in sorted(ports)]
    else:
        commands.append(f"-X {CHAIN}")
    commands.append("COMMIT")
    run(["iptables-restore", "--wait", "--noflush"], input=("\n".join(commands) + "\n").encode())


def configure_hooks():
    changed = False
    for core in vps.ORDER:
        unit = vps.UNITS / vps.SPECS[core][1]
        folder = vps.UNITS / (unit.name + ".d")
        path = folder / "20-rayzento-firewall.conf"
        if path.is_symlink() or folder.is_symlink():
            raise vps.Failure("防火墙启动配置是符号链接。")
        if folder.exists():
            vps.root_owned_path(folder)
        if path.exists():
            vps.root_owned_path(path)
        if path.exists() and path.read_text() != HOOK_TEXT:
            raise vps.Failure("同名防火墙启动配置已被修改，未覆盖。")
        if not unit.exists():
            if path.exists():
                path.unlink()
                changed = True
                if not any(folder.iterdir()):
                    folder.rmdir()
            continue
        vps.root_owned_path(unit)
        if unit.is_symlink() or f"ExecStart={vps.OPT / core / core} " not in unit.read_text():
            raise vps.Failure("服务文件不属于预期的 RayZento 核心。")
        if not path.exists():
            folder.mkdir(mode=0o755, exist_ok=True)
            vps.root_owned_path(folder)
            path.write_text(HOOK_TEXT)
            path.chmod(0o644)
            changed = True
    if changed:
        run(["systemctl", "daemon-reload"])


def sync(*, extra=(), clear=False, hooks=True):
    if vps.ROOT.is_symlink():
        raise vps.Failure("防火墙状态目录是符号链接。")
    vps.ROOT.mkdir(mode=0o700, exist_ok=True)
    vps.root_owned_path(vps.ROOT)
    lockfile = vps.ROOT / "firewall.lock"
    if lockfile.is_symlink():
        raise vps.Failure("防火墙锁是符号链接。")
    if lockfile.exists():
        vps.root_owned_path(lockfile)
    with lockfile.open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        ports = set() if clear else desired_ports() | set(extra)
        if any(proto not in ("tcp", "udp") or type(port) is not int or not 1 <= port <= 65535 for proto, port in ports):
            raise vps.Failure("防火墙端口无效。")
        backend, data = detect()
        if backend == "ufw":
            apply_ufw(ports)
        elif backend == "firewalld":
            apply_firewalld(ports)
        elif backend == "nftables":
            apply_nftables(data, ports)
        elif backend == "iptables":
            apply_iptables(data, ports)
        if hooks:
            configure_hooks()
        if backend == "none":
            print("未发现启用的本机 INPUT 过滤；未新建防火墙或修改默认策略。")
        else:
            print(f"{backend}：已同步 RayZento IPv4 端口：" + (", ".join(f"{port}/{proto}" for proto, port in sorted(ports)) or "无"))
        return backend
