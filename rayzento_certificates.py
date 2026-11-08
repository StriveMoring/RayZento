"""Certbot HTTP-01 provisioning and restricted deploy hooks for RayZento."""
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import tempfile

import rayzento_core as vps

HOOK = Path("/etc/letsencrypt/renewal-hooks/deploy/80-rayzento")
LE = Path("/etc/letsencrypt")
CERT_NAME = re.compile(r"rz-[a-z0-9.-]+")


def domain(value):
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or "." not in value or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part) for part in value.split(".")):
        raise vps.Failure("需要有效的证书域名。")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise vps.Failure("此证书入口需要域名。")


def install_packages(names):
    missing = [name for name in names
               if vps.command(["dpkg-query", "-W", "-f=${db:Status-Status}", name], check=False).stdout != b"installed"]
    if missing:
        vps.command(["apt-get", "update"], timeout=300)
        vps.command(["apt-get", "install", "-y", "--no-install-recommends", *missing], timeout=300,
                    env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"})


def managed():
    folder = vps.ROOT / "certificates"
    if not folder.exists():
        return []
    if folder.is_symlink():
        raise vps.Failure("证书状态目录是符号链接。")
    vps.root_owned_path(folder)
    results = []
    for path in sorted(folder.glob("rz-*.json")):
        if path.is_symlink():
            raise vps.Failure("证书记录是符号链接。")
        vps.root_owned_path(path)
        data = json.loads(path.read_text())
        if not CERT_NAME.fullmatch(data["name"]) or path.stem != data["name"]:
            raise vps.Failure("证书记录名称不符。")
        domain(data["domain"])
        results.append(data)
    return results


def copy_cert(data):
    import rayzento_provision as provision
    lineage = LE / "live" / data["name"]
    destination = vps.ROOT / "certificates" / data["name"]
    destination.mkdir(mode=0o700, parents=True, exist_ok=True)
    vps.root_owned_path(destination)
    cert = (lineage / "fullchain.pem").resolve(strict=True)
    key = (lineage / "privkey.pem").resolve(strict=True)
    if not cert.is_relative_to(LE) or not key.is_relative_to(LE):
        raise vps.Failure("证书不在受管 Let's Encrypt 目录内。")
    provision.tls_check(cert, key, data["domain"])
    with tempfile.TemporaryDirectory(prefix=".renew-", dir=destination) as tmp:
        staged = Path(tmp)
        for source, name in ((cert, "fullchain.pem"), (key, "privkey.pem")):
            target = staged / name
            shutil.copyfile(source, target)
            target.chmod(0o600)
        # All consumers are restarted only after both new files have been copied and validated.
        provision.tls_check(staged / "fullchain.pem", staged / "privkey.pem", data["domain"])
        before = {name: (destination / name).read_bytes() if (destination / name).exists() else None
                  for name in ("fullchain.pem", "privkey.pem")}
        try:
            for name in before:
                os.replace(staged / name, destination / name)
            vps.syncdir(destination)
        except BaseException:
            for name, content in before.items():
                target = destination / name
                if content is None:
                    target.unlink(missing_ok=True)
                else:
                    target.write_bytes(content)
                    target.chmod(0o600)
            raise
    return destination / "fullchain.pem", destination / "privkey.pem"


def issue(hostname, public_ipv4):
    import rayzento_provision as provision
    hostname = domain(hostname)
    existing = next((c for c in managed() if c["domain"] == hostname), None)
    if existing:
        try:
            cert, key = copy_cert(existing)
        except vps.Failure:
            vps.command(["certbot", "renew", "--cert-name", existing["name"]], timeout=240)
            cert, key = copy_cert(existing)
        ensure_renewal()
        return cert, key
    addresses = {record[4][0] for record in socket.getaddrinfo(hostname, 80, type=socket.SOCK_STREAM)}
    if public_ipv4 not in addresses:
        raise vps.Failure(f"{hostname} 的 DNS 未指向识别到的公网入口 {public_ipv4}。请先修改 DNS。")
    if any(ipaddress.ip_address(a).version == 6 for a in addresses):
        raise vps.Failure("域名含 AAAA 记录。当前按 IPv4 部署，请先确认并移除错误的 AAAA，或提供自有证书。")
    if 80 in provision.listening_ports():
        raise vps.Failure("80 端口已有服务。可提供自有证书，或先自行处理 HTTP-01 端口。")
    install_packages(["certbot"])
    name = "rz-" + hostname
    print("自动申请使用 Let's Encrypt HTTP-01。DNS 必须指向本机，安全组需放行 TCP 80。")
    vps.command(["certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos",
                 "--register-unsafely-without-email", "--preferred-challenges", "http",
                 "--cert-name", name, "-d", hostname], timeout=240)
    with vps.lock():
        folder = vps.ROOT / "certificates"
        folder.mkdir(mode=0o700, exist_ok=True)
        data = {"name": name, "domain": hostname}
        cert, key = copy_cert(data)
        vps.atomic_json(folder / f"{name}.json", data)
    ensure_renewal()
    return cert, key


def ensure_renewal():
    executable = Path("/usr/local/bin/rayzento")
    if executable.is_symlink() or not executable.is_file():
        raise vps.Failure("请先注册 rayzento 管理命令，证书续期任务需要调用它。")
    vps.root_owned_path(executable)
    content = "#!/bin/sh\n# Managed by RayZento\nexec /usr/local/bin/rayzento certificate deploy\n"
    HOOK.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    vps.root_owned_path(HOOK.parent)
    if HOOK.is_symlink() or (HOOK.exists() and HOOK.read_text() != content):
        raise vps.Failure("同名证书部署 hook 已存在其他内容。")
    HOOK.write_text(content)
    HOOK.chmod(0o700)
    vps.command(["systemctl", "enable", "--now", "certbot.timer"], timeout=35)
    vps.command(["systemctl", "is-active", "--quiet", "certbot.timer"])


def deploy():
    renewal = os.environ.get("RENEWED_LINEAGE", "")
    with vps.lock():
        for data in managed():
            if renewal and Path(renewal) != LE / "live" / data["name"]:
                continue
            destination = vps.ROOT / "certificates" / data["name"]
            cert, key = destination / "fullchain.pem", destination / "privkey.pem"
            previous = {path: path.read_bytes() for path in (cert, key) if path.exists()}
            related = []
            for core in vps.ORDER:
                config = vps.OPT / core / "server.json"
                if not config.exists():
                    continue
                svc = vps.inspect(core, require_running=False)
                text = config.read_text()
                if str(cert) not in text or str(key) not in text or not svc.pid:
                    continue
                related.append(svc)
            try:
                copy_cert(data)
                for svc in related:
                    vps.command(vps.config_check(svc.core, svc.exe, svc.config), timeout=35)
                    vps.boot(svc.unit, svc.exe, svc.ports, vps.sha(svc.exe))
            except BaseException:
                for path, content in previous.items():
                    with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as f:
                        candidate = Path(f.name)
                        try:
                            f.write(content)
                            f.flush()
                            os.fsync(f.fileno())
                            os.replace(candidate, path)
                        finally:
                            candidate.unlink(missing_ok=True)
                failures = []
                for svc in related:
                    try:
                        vps.boot(svc.unit, svc.exe, svc.ports, vps.sha(svc.exe))
                    except vps.Failure:
                        failures.append(svc.unit)
                if failures:
                    print("旧证书已恢复，仍需检查服务 " + ", ".join(failures))
                raise
    print("相关证书已部署，已运行的相关核心已恢复。")


def renew(*, dry_run=False):
    records = managed()
    if not records:
        raise vps.Failure("当前没有 RayZento 自动申请的证书。")
    for data in records:
        command = ["certbot", "renew", "--cert-name", data["name"]]
        if dry_run:
            command.append("--dry-run")
        vps.command(command, timeout=300)
    print("证书续期检查完成。")


def status():
    for data in managed():
        cert = vps.ROOT / "certificates" / data["name"] / "fullchain.pem"
        print(data["domain"])
        print(vps.command(["openssl", "x509", "-in", cert, "-noout", "-subject", "-dates"]).stdout.decode())
    print("certbot.timer " + vps.sysprop("certbot.timer", "ActiveState"))
