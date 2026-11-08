#!/usr/bin/env python3
"""RayZento 管理 VPS 核心和 Linux 小内存优化。"""
import argparse
import contextlib
import dataclasses
import datetime
import fcntl
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
import uuid
import zipfile

import rayzento_compat as compatibility

ROOT = Path("/var/lib/rayzento")
OPT = Path("/opt/rayzento")
UNITS = Path("/etc/systemd/system")
VERSION = "2.1.0"
SPECS = {
    "xray": ("XTLS/Xray-core", "rayzento-xray.service"),
    "sing-box": ("SagerNet/sing-box", "rayzento-sing-box.service"),
    "mihomo": ("MetaCubeX/mihomo", "rayzento-mihomo.service"),
}
ORDER = ("sing-box", "xray", "mihomo")
TAG = re.compile(r"v?[0-9]{1,4}\.[0-9]{1,3}\.[0-9]{1,3}")
TXID = re.compile(r"[0-9]{8}T[0-9]{6}Z-[0-9a-f]{8}")
FRESH_ID = re.compile(r"fresh-[a-z0-9_]{8}")
MAX_ASSET = 100 * 1024 * 1024
MAX_BINARY = 120 * 1024 * 1024
MAX_CONFIG = 8 * 1024 * 1024


class Failure(RuntimeError):
    pass


ACTION_ERRORS = (Failure, OSError, ValueError, KeyError, IndexError, zipfile.BadZipFile, tarfile.TarError)


def version(s):
    if not TAG.fullmatch(s):
        raise Failure("需要固定正式版标签，例如 v26.10.31；不接受 latest、alpha 或任意 URL。")
    return "v" + s.removeprefix("v")


def arch():
    a = platform.machine().lower()
    if a not in compatibility.ARCHES:
        raise Failure(f"架构 {a} 未支持，需 amd64 或 arm64。")
    return compatibility.ARCHES[a]


def command(args, *, timeout=20, check=True, **kwargs):
    try:
        p = subprocess.run(list(map(str, args)), capture_output=True, timeout=timeout, **kwargs)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise Failure(f"{Path(args[0]).name} 执行失败：{type(e).__name__}") from None
    if check and p.returncode != 0:
        # 不输出 stderr：核心的配置错误可能包含密钥、UUID 或证书内容。
        raise Failure(f"{Path(args[0]).name} 返回 {p.returncode}。")
    return p


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def atomic_json(path, data):
    with tempfile.NamedTemporaryFile(mode="w", prefix=".rayzento-json-", dir=path.parent,
                                     encoding="utf-8", delete=False) as f:
        tmp = Path(f.name)
        try:
            json.dump(data, f, indent=2, ensure_ascii=False)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
            os.replace(tmp, path)
            syncdir(path.parent)
        finally:
            tmp.unlink(missing_ok=True)


def syncdir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class HTTPSRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        from urllib.parse import urlparse
        u = urlparse(newurl)
        if u.scheme != "https" or u.hostname not in (
            "github.com", "api.github.com", "release-assets.githubusercontent.com",
            "objects.githubusercontent.com",
        ):
            raise Failure("拒绝非 GitHub HTTPS 下载重定向。")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(url, cap, max_seconds=120):
    request = urllib.request.Request(url, headers={"User-Agent": "RayZento/2"})
    try:
        with urllib.request.build_opener(HTTPSRedirect()).open(request, timeout=25) as resp:
            chunks, total = [], 0
            deadline = time.monotonic() + max_seconds
            while True:
                block = resp.read(128 * 1024)
                if not block:
                    break
                total += len(block)
                if total > cap:
                    raise Failure("官方发布下载超出大小限制。")
                if time.monotonic() > deadline:
                    raise Failure("官方发布下载超出时间限制。")
                chunks.append(block)
            return b"".join(chunks)
    except (OSError, ValueError) as e:
        raise Failure(f"GitHub HTTPS 下载失败：{type(e).__name__}") from None


def release(core, tag=None):
    repo = SPECS[core][0]
    tail = "latest" if tag is None else "tags/" + version(tag)
    obj = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases/{tail}", 4 * 1024 * 1024))
    actual = version(obj.get("tag_name", ""))
    if obj.get("draft") or obj.get("prerelease") or (tag and actual != version(tag)):
        raise Failure(f"{core} 返回的发布不是指定的正式版。")
    return obj


def release_asset(core, obj, machine):
    tag = version(obj["tag_name"])
    name = (
        {"amd64": "Xray-linux-64.zip", "arm64": "Xray-linux-arm64-v8a.zip"}[machine]
        if core == "xray" else f"mihomo-linux-{machine}-{tag}.gz" if core == "mihomo"
        else f"sing-box-{tag[1:]}-linux-{machine}.tar.gz"
    )
    assets = [a for a in obj.get("assets", []) if a.get("name") == name]
    if len(assets) != 1:
        raise Failure(f"{core} 正式版缺少预期架构文件 {name}。")
    a = assets[0]
    expected_url = f"https://github.com/{SPECS[core][0]}/releases/download/{tag}/{name}"
    if a.get("browser_download_url") != expected_url:
        raise Failure("GitHub 资产 URL 不符合固定仓库、版本和文件名。")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", a.get("digest") or ""):
        raise Failure("官方 Release API 未提供 SHA-256；不跳过验证。")
    if not isinstance(a.get("size"), int) or not 0 < a["size"] <= MAX_ASSET:
        raise Failure("官方资产大小不在允许范围内。")
    return a


def binary_from_archive(core, obj, machine):
    a = release_asset(core, obj, machine)
    data = fetch(a["browser_download_url"], a["size"], max_seconds=300)
    if len(data) != a["size"] or "sha256:" + hashlib.sha256(data).hexdigest() != a["digest"]:
        raise Failure(f"{core} 下载文件校验失败。")
    with io.BytesIO(data) as raw:
        if core == "xray":
            with zipfile.ZipFile(raw) as archive:
                matches = [m for m in archive.infolist() if m.filename == "xray"]
                if len(matches) != 1:
                    raise Failure("Xray 归档中未找到唯一的 xray 文件。")
                m = matches[0]
                mode = stat.S_IFMT(m.external_attr >> 16)
                if m.is_dir() or mode not in (0, stat.S_IFREG) or not 0 < m.file_size <= MAX_BINARY:
                    raise Failure("Xray 归档成员不是受支持的普通文件。")
                blob = archive.read(m)
        elif core == "mihomo":
            with gzip.GzipFile(fileobj=raw) as archive:
                blob = archive.read(MAX_BINARY + 1)
                if len(blob) > MAX_BINARY:
                    raise Failure("Mihomo 解包超过大小限制。")
        else:
            member = a["name"].removesuffix(".tar.gz") + "/sing-box"
            with tarfile.open(fileobj=raw, mode="r:gz") as archive:
                matches = [m for m in archive if m.name == member]
                if len(matches) != 1 or not matches[0].isfile() or not 0 < matches[0].size <= MAX_BINARY:
                    raise Failure("sing-box 归档成员不是受支持的普通文件。")
                with archive.extractfile(matches[0]) as f:
                    blob = f.read(MAX_BINARY + 1)
    if (
        len(blob) < 64 or blob[:6] != b"\x7fELF\x02\x01"
        or int.from_bytes(blob[18:20], "little") != {"amd64": 62, "arm64": 183}[machine]
    ):
        raise Failure("二进制不是预期的 Linux ELF64 架构。")
    return blob, a["digest"]


def root_owned_path(p):
    for candidate in (p, *p.parents):
        st = candidate.stat()
        if st.st_uid != 0 or st.st_mode & 0o022:
            raise Failure(f"路径可由非 root 用户改写：{candidate}")


def core_command(core, exe, config):
    if core == "mihomo":
        return [exe, "-d", config.parent, "-f", config]
    return [exe, "run", "-c", config]


def config_check(core, exe, config):
    if core == "mihomo":
        return [exe, "-t", "-d", config.parent, "-f", config]
    if core == "xray":
        return [exe, "run", "-test", "-c", config]
    return [exe, "check", "-c", config]


def release_record(core, tag, digest, binary_sha):
    return {"repository": SPECS[core][0], "tag": tag, "architecture": arch(),
            "archive_sha256": digest, "binary_sha256": binary_sha}


def installed_release(core, binary_sha):
    origin_path = OPT / core / "origin.json"
    if origin_path.is_symlink():
        raise Failure("安装来源记录不能是符号链接。")
    root_owned_path(origin_path)
    root_owned_path(ROOT)
    origin = json.loads(origin_path.read_text())
    records = [origin]
    if origin.get("binary_sha256") != binary_sha:
        for transaction in ROOT.iterdir():
            if transaction.is_symlink() or not TXID.fullmatch(transaction.name):
                continue
            manifest = transaction / "manifest.json"
            if not manifest.is_file() or manifest.is_symlink():
                continue
            root_owned_path(manifest)
            data = json.loads(manifest.read_text())
            if data.get("id") == transaction.name:
                records.extend(r["release"] for r in data.get("cores", [])
                               if r.get("core") == core and "release" in r)
    for record in records:
        if (record.get("repository") == SPECS[core][0] and record.get("architecture") == arch()
                and re.fullmatch(r"sha256:[0-9a-f]{64}", record.get("archive_sha256", ""))
                and record.get("binary_sha256") == binary_sha):
            version(record["tag"])
            return record
    raise Failure(f"{core} 的二进制与官方安装或升级记录不一致。")


def sysprop(unit, name):
    return command(["systemctl", "show", "--value", "-p", name, unit]).stdout.decode().strip()


def listeners(pid):
    p = command(["ss", "-H", "-lntup"]).stdout.decode(errors="replace")
    match = re.compile(rf"\bpid={pid}(?=\D|$)")
    return sorted({f"{z[0]} {z[4]}" for ln in p.splitlines() if match.search(ln) and len(z := ln.split()) >= 6})


def version_banner(exe, core=None):
    name = core or exe.name
    result = command([exe, "-v" if name == "mihomo" else "version"], check=False)
    if result.returncode:
        error = result.stderr.decode(errors="replace")
        glibc = re.search(r"\bGLIBC_([0-9]+(?:\.[0-9]+)+)\b[^\n]*not found", error)
        if glibc:
            raise Failure(f"{name} 的官方发布包需要 glibc {glibc[1]}，当前 VPS 缺少该版本。")
        raise Failure(f"{name} 的官方二进制无法在当前 VPS 运行，退出码 {result.returncode}。")
    s = result.stdout.decode(errors="replace").splitlines()
    if not s:
        raise Failure("核心未返回版本。")
    return s[0][:200]


def parse_banner(core, banner):
    prefix = {"xray": "Xray ", "sing-box": "sing-box version ", "mihomo": "Mihomo Meta "}[core]
    if not banner.startswith(prefix):
        raise Failure(f"运行文件不是预期的 {core} 核心。")
    return version(banner.removeprefix(prefix).split()[0])


@dataclasses.dataclass
class Service:
    core: str
    unit: str
    pid: int
    exe: Path
    config: Path
    ports: list
    old: str
    origin: dict


def inspect(core, *, require_running=True):
    unit = SPECS[core][1]
    exe = OPT / core / core
    config = exe.parent / "server.json"
    fragment = UNITS / unit
    if sysprop(unit, "LoadState") != "loaded" or sysprop(unit, "FragmentPath") != str(fragment):
        raise Failure(f"{unit} 不是本工具安装的服务。")
    if sysprop(unit, "DropInPaths"):
        raise Failure(f"{unit} 存在额外的 systemd 覆盖配置。")
    active = sysprop(unit, "ActiveState") == "active"
    if (require_running and not active) or sysprop(unit, "Type") != "simple":
        raise Failure(f"{unit} 未处于预期的运行状态。")
    for path in (fragment, exe, config):
        if path.is_symlink() or not path.is_file():
            raise Failure(f"受管文件缺失或是符号链接：{path}")
        root_owned_path(path)
    if exe.stat().st_mode & (stat.S_ISUID | stat.S_ISGID) or config.stat().st_size > MAX_CONFIG:
        raise Failure("核心文件权限或配置大小不符合受管布局。")
    pid = int(sysprop(unit, "MainPID") or "0")
    if require_running and pid <= 1:
        raise Failure("找不到服务主进程。")
    if active:
        if pid <= 1:
            raise Failure("服务标记运行但未找到主进程。")
        proc = Path(f"/proc/{pid}")
        running_exe = proc / "exe"
        expected = list(map(str, core_command(core, exe, config)))
        actual = [os.fsdecode(a) for a in (proc / "cmdline").read_bytes().split(b"\0") if a]
        if (running_exe.resolve(strict=True) != exe or not os.path.samestat(running_exe.stat(), exe.stat())
                or actual != expected):
            raise Failure(f"{unit} 实际运行的文件或启动参数与受管布局不符。")
    start_paths = re.findall(r"\bpath=([^ ;}]+)", sysprop(unit, "ExecStart"))
    if start_paths != [str(exe)]:
        raise Failure("systemd 配置与实际核心路径不一致。")
    origin = installed_release(core, sha(exe))
    ports = listeners(pid) if active else []
    if require_running and not ports:
        raise Failure("当前主进程没有可核对的 TCP/UDP 监听。")
    return Service(core, unit, pid, exe, config, ports, origin["tag"], origin)


def requires_reality_preflight(svc, tag):
    if svc.core != "xray" or tag_numbers(tag) < (26, 9, 8):
        return False
    return bool(re.search(r'"security"\s*:\s*"reality"', svc.config.read_text(), re.I))


def copy_identity(src, dst):
    st = src.stat()
    os.chown(dst, st.st_uid, st.st_gid)
    shutil.copystat(src, dst)
    with dst.open("rb") as f:
        os.fsync(f.fileno())


def stage_binary(svc, blob):
    with tempfile.NamedTemporaryFile(prefix=".rayzento-candidate-", dir=svc.exe.parent, delete=False) as t:
        stage = Path(t.name)
        t.write(blob)
        t.flush()
        os.fsync(t.fileno())
    try:
        copy_identity(svc.exe, stage)
        # copystat carries Linux security.capability and mode; if preservation fails, stop.
        for k in ("security.capability",):
            source = k in os.listxattr(svc.exe)
            dest = k in os.listxattr(stage)
            if source != dest or source and os.getxattr(svc.exe, k) != os.getxattr(stage, k):
                raise Failure(f"候选文件未能继承 {k}。")
        return stage
    except BaseException:
        stage.unlink(missing_ok=True)
        raise


def running_match(unit, exe, expected_ports, expect_sha):
    pid = int(sysprop(unit, "MainPID") or "0")
    if pid <= 1 or sysprop(unit, "ActiveState") != "active":
        return False
    p = Path(f"/proc/{pid}/exe")
    try:
        return p.resolve(strict=True) == exe and os.path.samestat(p.stat(), exe.stat()) and sha(exe) == expect_sha and set(expected_ports) <= set(listeners(pid))
    except OSError:
        return False


def boot(unit, exe, expected_ports, expect_sha):
    command(["systemctl", "restart", unit], timeout=45)
    deadline = time.monotonic() + 12
    good = 0
    while time.monotonic() < deadline:
        good = good + 1 if running_match(unit, exe, expected_ports, expect_sha) else 0
        if good >= 2:
            return
        time.sleep(1)
    raise Failure(f"{unit} 未恢复原监听或未运行指定版本。")


def restore(record, tx):
    exe = Path(record["exe"])
    root_owned_path(exe)
    if exe.is_symlink():
        raise Failure("回滚目标路径变成了符号链接。")
    source = tx / record["core"] / "binary.before"
    if sha(source) != record["before_sha"]:
        raise Failure("旧核心备份校验失败。")
    now = sha(exe)
    if now == record["before_sha"]:
        if not running_match(record["unit"], exe, record["ports"], now):
            boot(record["unit"], exe, record["ports"], now)
        return
    if now != record["after_sha"]:
        raise Failure("当前二进制不是该交易所安装的版本；不覆盖后续变更。")
    with tempfile.NamedTemporaryFile(prefix=".rayzento-rollback-", dir=exe.parent, delete=False) as t:
        stage = Path(t.name)
    try:
        shutil.copyfile(source, stage)
        copy_identity(source, stage)
        if "security.capability" in os.listxattr(source) and os.getxattr(stage, "security.capability") != os.getxattr(source, "security.capability"):
            raise Failure("回滚文件能力未保留。")
        with stage.open("rb") as f:
            os.fsync(f.fileno())
        os.replace(stage, exe)
        syncdir(exe.parent)
        boot(record["unit"], exe, record["ports"], record["before_sha"])
    finally:
        stage.unlink(missing_ok=True)


def host_check():
    problems = compatibility.inspect().problems()
    if problems:
        raise Failure(" ".join(problems))
    if os.geteuid() != 0:
        raise Failure("此命令需要 sudo。")


@contextlib.contextmanager
def lock():
    ROOT.mkdir(mode=0o700, exist_ok=True)
    if ROOT.is_symlink() or ROOT.stat().st_mode & 0o077:
        raise Failure("回滚目录必须为 root 私有目录（0700）。")
    root_owned_path(ROOT)
    with (ROOT / "lock").open("a") as f:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Failure("该 VPS 已有另一项升级/回滚。") from None
        yield


def apply(targets, reality_ready, latest=()):
    with lock():
        txid = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ-") + uuid.uuid4().hex[:8]
        tx = ROOT / txid
        selected = [(inspect(c), targets[c]) for c in ORDER if c in targets]
        for svc, tag in selected:
            if svc.core in latest and tag_numbers(tag) < tag_numbers(svc.old):
                raise Failure(f"{svc.core} 的官方最新正式版低于当前版本；拒绝隐式降级。")
        selected = [(s, tag) for s, tag in selected if s.old != tag]
        if not selected:
            print("指定版本已在运行，无需重启。")
            return
        for svc, tag in selected:
            if requires_reality_preflight(svc, tag) and not reality_ready:
                raise Failure("新版 Xray 配置含 REALITY：先为这台准备隔离客户端的 Chrome + ML-KEM，再用 --reality-client-ready 确认。")
        tx.mkdir(mode=0o700)
        print(f"本次回滚编号：{txid}", flush=True)
        stages, records, changed = {}, [], []
        manifest = {"id": txid, "state": "staging", "cores": records}
        try:
            for svc, tag in selected:
                key = svc.core
                saved = sha(svc.config)
                blob, digest = binary_from_archive(key, release(key, tag), arch())
                p = stage_binary(svc, blob)
                stages[key] = p
                original = sha(svc.exe)
                candidate = sha(p)
                found = parse_banner(key, version_banner(p, key))
                command(config_check(key, p, svc.config), timeout=35)
                if found != tag or sha(svc.config) != saved:
                    raise Failure("候选版本不符或配置在校验期间发生变化。")
                bd = tx / key
                bd.mkdir(mode=0o700)
                shutil.copyfile(svc.exe, bd / "binary.before")
                copy_identity(svc.exe, bd / "binary.before")
                shutil.copyfile(svc.config, bd / "server.json.backup")
                if sha(bd / "binary.before") != original:
                    raise Failure("备份核心校验失败。")
                for f in bd.iterdir():
                    with f.open("rb") as fd:
                        os.fsync(fd.fileno())
                syncdir(bd)
                records.append({"core": key, "unit": svc.unit, "exe": str(svc.exe), "ports": svc.ports,
                                "old": svc.old, "target": tag, "before_sha": original,
                                "after_sha": candidate, "config_sha256": saved,
                                "release": release_record(key, tag, digest, candidate)})
                print(f"{key} {svc.old} → {tag}：官方指纹、实际配置校验、旧版备份均通过。", flush=True)
            manifest["state"] = "ready"
            atomic_json(tx / "manifest.json", manifest)
            for (svc, _), rec in zip(selected, records):
                if sha(svc.exe) != rec["before_sha"] or sha(svc.config) != rec["config_sha256"] or int(sysprop(svc.unit, "MainPID")) != svc.pid:
                    raise Failure(f"{svc.unit} 在预检后变化；不覆盖。")
                changed.append(rec)
                os.replace(stages[svc.core], svc.exe)
                syncdir(svc.exe.parent)
                boot(svc.unit, svc.exe, svc.ports, rec["after_sha"])
                print(f"{svc.unit} 已用新核心启动，原监听已恢复。", flush=True)
            manifest["state"] = "local-verified"
            atomic_json(tx / "manifest.json", manifest)
            print("本机监听验收通过。请从 v2rayN 和 RayZento 实测涉及的入站及公网出口。")
            print(f"回滚命令：sudo rayzento rollback {txid}")
        except BaseException:
            if changed:
                errors = []
                for rec in reversed(changed):
                    try:
                        restore(rec, tx)
                    except Exception as e:
                        errors.append(f"{rec['core']}: {e}")
                manifest["state"] = "rollback-incomplete" if errors else "rolled-back"
                atomic_json(tx / "manifest.json", manifest)
                print("自动回滚：" + ("；".join(errors) if errors else "已恢复本次替换的核心。"), file=sys.stderr)
            raise
        finally:
            for p in stages.values():
                p.unlink(missing_ok=True)


def rollback(txid):
    if not TXID.fullmatch(txid):
        raise Failure("回滚编号格式无效。")
    with lock():
        tx = ROOT / txid
        root_owned_path(tx)
        manifest = json.loads((tx / "manifest.json").read_text())
        if manifest.get("id") != txid or not manifest.get("cores"):
            raise Failure("没有有效的已备份交易。")
        errors = []
        for rec in reversed(manifest["cores"]):
            if (rec["core"] not in SPECS or rec["unit"] != SPECS[rec["core"]][1]
                    or Path(rec["exe"]) != OPT / rec["core"] / rec["core"]):
                raise Failure("回滚清单包含未知单元。")
            try:
                restore(rec, tx)
                print(f"{rec['unit']} 已处于备份版本。")
            except Exception as e:
                errors.append(str(e))
        manifest["state"] = "rollback-incomplete" if errors else "rolled-back"
        atomic_json(tx / "manifest.json", manifest)
        if errors:
            raise Failure("；".join(errors))


def tag_numbers(tag):
    return tuple(map(int, tag.removeprefix("v").split(".")))


def main(argv=None):
    import rayzento_provision as provision
    import rayzento_menu as menu
    import rayzento_tune as tuning

    p = argparse.ArgumentParser(prog="rayzento", description=__doc__)
    p.add_argument("--version", action="version", version=f"RayZento {VERSION}")
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("menu", help="打开交互式数字菜单")
    sub.add_parser("doctor", help="只读检查系统、VPS 环境和功能兼容性")
    registration = sub.add_parser("register", help="安装或更新系统管理命令")
    registration.add_argument("--yes", action="store_true", help="直接注册当前发布文件")
    sub.add_parser("profiles", help="列出协议和安装预设")
    provision.add_install_options(sub.add_parser("install", help="从官方正式版创建并安装新节点"))
    activation = sub.add_parser("activate", help="启用已经校验的安装候选")
    activation.add_argument("candidate", metavar="FRESH-ID")
    activation.add_argument("--reality-client-ready", action="store_true")
    sub.add_parser("releases", help="只查询官方最新正式版；不会更新")
    sub.add_parser("audit", help="只读取此 VPS 的服务归属和端口")
    certificate = sub.add_parser("certificate", help="证书状态、续期和自动部署")
    certificate.add_argument("certificate_action", choices=("status", "renew", "dry-run", "deploy"))
    node = sub.add_parser("nodes", help="节点链接、二维码和客户端导出")
    node.add_argument("node_action", choices=("show", "export"))
    tuning.add_commands(sub.add_parser("tune", help="管理 Swap、Journald 和 BBR/FQ"))
    for name in ("plan", "upgrade"):
        a = sub.add_parser(name, help="核对目标版本" if name == "plan" else "校验、备份和替换指定核心")
        for c in SPECS:
            a.add_argument(f"--{c}-version", dest=c, type=version)
        a.add_argument("--latest", nargs="+", choices=tuple(SPECS), default=(),
                       help="查询指定核心的官方正式版；仅 upgrade 会安装")
        if name == "upgrade":
            a.add_argument("--reality-client-ready", action="store_true")
    sub.add_parser("rollback", help="恢复一次交易的原核心").add_argument("transaction")
    if argv is None:
        argv = sys.argv[1:]
        if not argv:
            argv = ["menu"] if sys.stdin.isatty() and sys.stdout.isatty() else ["--help"]
    args = p.parse_args(argv)
    os.umask(0o077)
    if args.action == "menu":
        menu.run()
        return
    if args.action == "doctor":
        if not compatibility.report():
            sys.exit(2)
        return
    if args.action == "register":
        menu.register_command(confirmed=args.yes)
        return
    if args.action == "profiles":
        for name, (core, title, transport) in provision.NAMES.items():
            print(f"{name:20} {core:9} {'/'.join(transport):7} {title}")
        for preset, names in provision.PRESETS.items():
            print(f"{preset}: {', '.join(names)}")
        return
    if args.action == "releases":
        for c in ORDER:
            obj = release(c)
            print(f"{c}: {obj['tag_name']} {obj['html_url']}")
        return
    host_check()
    if args.action == "certificate":
        import rayzento_certificates as certificates
        actions = {"status": certificates.status, "renew": certificates.renew,
                   "dry-run": lambda: certificates.renew(dry_run=True), "deploy": certificates.deploy}
        actions[args.certificate_action]()
        return
    if args.action == "nodes":
        import rayzento_nodes as nodes
        (nodes.display if args.node_action == "show" else nodes.export)()
        return
    if args.action == "tune":
        tuning.run(args)
        return
    if args.action == "install":
        provision.install(args)
        return
    if args.action == "activate":
        if not FRESH_ID.fullmatch(args.candidate):
            p.error("activate 仅接收先前生成的 fresh-ID。")
        with lock():
            provision.activate(ROOT / args.candidate, args.reality_client_ready)
        return
    if args.action == "rollback":
        rollback(args.transaction)
        return
    if args.action == "audit":
        unsupported = False
        for c in ORDER:
            if sysprop(SPECS[c][1], "LoadState") == "not-found" and not (OPT / c).exists():
                print(f"{c}: 未安装。")
                continue
            try:
                s = inspect(c, require_running=False)
                print(f"{c}: {s.old} · {sysprop(s.unit, 'ActiveState')} · 自启 {sysprop(s.unit, 'UnitFileState')}")
                print(f"  {s.unit} {s.exe} | {', '.join(s.ports)}")
                print(f"  官方来源 {s.origin['repository']} | {s.origin['archive_sha256']}")
            except (Failure, OSError, ValueError) as e:
                print(f"{c}: 不自动接管。{e}")
                unsupported = True
        if unsupported:
            sys.exit(2)
        return
    targets = {c: getattr(args, c) for c in SPECS if getattr(args, c)}
    if targets.keys() & set(args.latest):
        p.error("同一核心只能用固定版本或 --latest。")
    targets.update({c: version(release(c)["tag_name"]) for c in dict.fromkeys(args.latest)})
    if not targets:
        p.error("至少指定一个固定正式版本或用 --latest 选择已安装的核心。")
    if args.action == "upgrade":
        apply(targets, args.reality_client_ready, args.latest)
    else:
        for c in ORDER:
            if c in targets:
                s = inspect(c)
                obj = release(c, targets[c])
                a = release_asset(c, obj, arch())
                print(f"{c}: {s.old} → {targets[c]} | {a['name']} {a['digest']}")
                print(f"  单元 {s.unit}；监听：{', '.join(s.ports)}")
                if requires_reality_preflight(s, targets[c]):
                    print("  REALITY：需先完成 Chrome + ML-KEM 客户端预检。")


def interrupt(_number, _frame):
    raise KeyboardInterrupt


def cli():
    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    try:
        main()
    except ACTION_ERRORS as error:
        print(f"停止：{error}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("操作中断。请核对运行状态和回退记录。", file=sys.stderr)
        sys.exit(130)
