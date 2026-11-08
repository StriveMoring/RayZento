"""Small VPS tuning for supported Linux systemd hosts."""
import argparse
import os
from pathlib import Path
import json
import re
import shutil
import stat
import tempfile
import time
import uuid

import homegateway_vps as vps
import rayzento_compat as compatibility

MIB = 1024 * 1024
RESERVE = 1024 * MIB
SWAP = Path("/swapfile")
FSTAB = Path("/etc/fstab")
MEMORY = Path("/etc/sysctl.d/99-rayzento-memory.conf")
NETWORK = Path("/etc/sysctl.d/99-rayzento-network.conf")
MODULE = Path("/etc/modules-load.d/90-rayzento-bbr.conf")
JOURNAL = Path("/etc/systemd/journald.conf.d/90-rayzento.conf")
JOURNAL_STORAGE = Path("/var/log/journal")
SYSCTL_DIRS = tuple(Path(p) for p in (
    "/etc/sysctl.d", "/run/sysctl.d", "/usr/local/lib/sysctl.d", "/usr/lib/sysctl.d", "/lib/sysctl.d",
))
TUNE_ID = re.compile(r"tune-[0-9]{19}-[0-9a-f]{8}")
SWAPPINESS = "vm.swappiness"
QDISC = "net.core.default_qdisc"
BBR = "net.ipv4.tcp_congestion_control"
ALGORITHMS = "net.ipv4.tcp_available_congestion_control"


def output(args):
    return vps.command(args).stdout.decode(errors="replace").strip()


def kernel(key):
    return output(["sysctl", "-n", key])


def set_kernel(key, value):
    vps.command(["sysctl", "-w", f"{key}={value}"])
    if kernel(key) != value:
        raise vps.Failure(f"{key} 未生效。")


def read(path):
    if path.is_symlink():
        raise vps.Failure(f"拒绝修改符号链接 {path}。")
    if not path.exists():
        return None
    vps.root_owned_path(path)
    if not path.is_file():
        raise vps.Failure(f"{path} 不是普通文件。")
    return path.read_bytes().decode()


def write(path, contents):
    if contents is None:
        path.unlink(missing_ok=True)
        vps.syncdir(path.parent)
        return
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    vps.root_owned_path(path.parent)
    original = path.stat() if path.exists() else None
    with tempfile.NamedTemporaryFile(prefix=".rayzento-", dir=path.parent, delete=False) as f:
        staged = Path(f.name)
        try:
            if original:
                os.fchown(f.fileno(), original.st_uid, original.st_gid)
            os.fchmod(f.fileno(), stat.S_IMODE(original.st_mode) if original else 0o644)
            f.write(contents.encode())
            f.flush()
            os.fsync(f.fileno())
            os.replace(staged, path)
            vps.syncdir(path.parent)
        finally:
            staged.unlink(missing_ok=True)


def active_swap():
    return {fields[0]: int(fields[3]) for line in Path("/proc/swaps").read_text().splitlines()[1:]
            if len(fields := line.split()) >= 5}


def fstab_swap(text):
    return [fields[0] for line in text.splitlines() if len(fields := line.split()) >= 3
            and not fields[0].startswith("#") and fields[2] == "swap"]


def sysctl_conflicts(settings):
    files = {}
    for directory in SYSCTL_DIRS:
        for path in directory.glob("*.conf"):
            files.setdefault(path.name, path)
    for key, (filename, desired) in settings.items():
        for name, path in sorted(files.items()):
            if name <= filename:
                continue
            for line in path.read_text(errors="replace").splitlines():
                k, sep, value = line.split("#", 1)[0].partition("=")
                k = k.strip().lstrip("-").replace("/", ".")
                if sep and k == key and value.strip() != desired:
                    raise vps.Failure(f"{path} 会覆盖 {key} 的开机配置。")


def journal_options():
    config = output(["systemd-analyze", "cat-config", "systemd/journald.conf"])
    values, section = {}, ""
    for line in config.splitlines():
        line = line.strip()
        if line.startswith("["):
            section = line
        if section == "[Journal]" and not line.startswith(("#", ";")):
            key, sep, value = line.partition("=")
            if sep:
                values[key.strip()] = value.strip()
    return values


def restart_journal():
    vps.command(["systemctl", "restart", "systemd-journald.service"], timeout=35)
    vps.command(["systemctl", "is-active", "--quiet", "systemd-journald.service"])


def check_journal(limit):
    options = journal_options()
    if options.get("SystemMaxUse") != limit:
        raise vps.Failure("Journald 的实际合并配置与预期预算不一致。")
    mode = options.get("Storage", "auto")
    if mode in ("volatile", "none") or (mode == "auto" and not JOURNAL_STORAGE.is_dir()):
        print(f"Journald 当前未启用持久日志，Storage={mode}。SystemMaxUse 适用于持久日志。")


def boot_id():
    return Path("/proc/sys/kernel/random/boot_id").read_text().strip()


def build_plan(args):
    files, settings = {}, {}

    def add(path, desired, before=None, *, own=True):
        if own:
            before = read(path)
            if before is not None and not before.startswith(("# Managed by RayZento\n", "[Journal]\n# Managed by RayZento\n")):
                raise vps.Failure(f"{path} 已有其他内容。")
        if before != desired:
            files[str(path)] = {"before": before, "after": desired}

    swaps = active_swap()
    create = args.swap_mib > 0 and not swaps
    if create:
        existing = read(FSTAB)
        if existing is None or SWAP.exists() or SWAP.is_symlink() or fstab_swap(existing):
            raise vps.Failure("检测到已有或待启用的 Swap 配置。可用 --swap-mib 0 仅优化其他项目。")
        if output(["findmnt", "-n", "-o", "FSTYPE", "--target", "/"]) not in compatibility.SWAP_FILESYSTEMS:
            raise vps.Failure("自动创建 Swap 仅支持 ext4 和 XFS。")
        if shutil.disk_usage("/").free < args.swap_mib * MIB + RESERVE:
            raise vps.Failure("磁盘空间不足。创建 Swap 后须保留至少 1 GiB。")
        tail = "" if not existing or existing.endswith("\n") else "\n"
        add(FSTAB, existing + tail + f"{SWAP} none swap sw 0 0\n", existing, own=False)
    marker = "# Managed by RayZento\n"
    settings[SWAPPINESS] = (MEMORY.name, str(args.swappiness))
    add(MEMORY, marker + f"{SWAPPINESS}={args.swappiness}\n")
    add(JOURNAL, f"[Journal]\n{marker}SystemMaxUse={args.journal_mib}M\n")
    if args.bbr:
        if "bbr" not in kernel(ALGORITHMS).split():
            vps.command(["modinfo", "tcp_bbr"])
        settings.update({QDISC: (NETWORK.name, "fq"), BBR: (NETWORK.name, "bbr")})
        add(NETWORK, marker + f"{QDISC}=fq\n{BBR}=bbr\n")
        add(MODULE, marker + "tcp_bbr\n")
    sysctl_conflicts(settings)
    runtime = {key: {"before": kernel(key), "after": value} for key, (_, value) in settings.items()}
    return {"files": files, "runtime": runtime, "swap_mib": args.swap_mib if create else 0,
            "reuse_swap": bool(swaps), "swap_inode": None, "journal_limit": f"{args.journal_mib}M"}


def print_plan(plan):
    if plan["swap_mib"]:
        print(f"创建 {plan['swap_mib']} MiB Swap，加入 {FSTAB}")
    elif plan["reuse_swap"]:
        print("沿用已启用的 Swap")
    else:
        print("本次未选择创建 Swap")
    for key, values in plan["runtime"].items():
        print(f"{key}: {values['before']} → {values['after']}")
    print(f"Journald 持久日志预算 {plan['journal_limit']}")
    for path in plan["files"]:
        print(f"持久化文件 {path}")


def guard_host():
    container = compatibility.container_status()
    if container is True:
        raise vps.Failure("内核调优仅用于独立 VPS。当前系统识别为容器。")
    if container is None:
        raise vps.Failure("无法确认宿主机的虚拟化类型。")


def create_swap(plan, record):
    size = plan["swap_mib"]
    if shutil.disk_usage("/").free < size * MIB + RESERVE:
        raise vps.Failure("磁盘剩余空间已变化。")
    fd = os.open(SWAP, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as f:
        inode = os.fstat(f.fileno())
        plan["swap_inode"] = [inode.st_dev, inode.st_ino]
        vps.atomic_json(record, plan)
    if vps.command(["fallocate", "-l", str(size * MIB), SWAP], check=False, timeout=60).returncode:
        vps.command(["dd", "if=/dev/zero", f"of={SWAP}", "bs=1M", f"count={size}", "conv=fsync"], timeout=300)
    vps.command(["mkswap", SWAP])
    if vps.command(["swapon", SWAP], check=False).returncode and str(SWAP) not in active_swap():
        # Some filesystems report preallocated extents as holes to swapon.
        vps.command(["dd", "if=/dev/zero", f"of={SWAP}", "bs=1M", f"count={size}", "conv=fsync"], timeout=300)
        vps.command(["mkswap", SWAP])
        vps.command(["swapon", SWAP])
    if str(SWAP) not in active_swap():
        raise vps.Failure("Swap 未出现在当前活动列表。")


def tune_records():
    for folder in sorted(vps.ROOT.glob("tune-*"), reverse=True):
        if folder.is_symlink() or not TUNE_ID.fullmatch(folder.name):
            continue
        record = folder / "tuning.json"
        data = read(record)
        if data is not None:
            yield record, json.loads(data)


def restore(record, plan):
    for path, values in plan["files"].items():
        if read(Path(path)) not in (values["before"], values["after"]):
            raise vps.Failure(f"{path} 在应用后被修改。保留现有内容。")
    for key, values in plan["runtime"].items():
        if kernel(key) not in (values["before"], values["after"]):
            raise vps.Failure(f"{key} 在应用后已被更改。")
    swap = plan["swap_inode"]
    remove_swap = bool(swap and (SWAP.exists() or SWAP.is_symlink()))
    if remove_swap:
        info = SWAP.lstat()
        if not stat.S_ISREG(info.st_mode) or [info.st_dev, info.st_ino] != swap:
            raise vps.Failure("Swap 文件身份已变化。保留现有文件。")
        current = active_swap()
        if current.get(str(SWAP), 0):
            raise vps.Failure("Swap 正在使用。请在释放内存并确认 Swap Used 为零后再回退。")
        if str(SWAP) in current:
            vps.command(["swapoff", SWAP], timeout=30)
            if str(SWAP) in active_swap():
                raise vps.Failure("Swap 仍处于启用状态。")
    for name, values in reversed(list(plan["files"].items())):
        path = Path(name)
        if read(path) != values["before"]:
            write(path, values["before"])
    if str(FSTAB) in plan["files"]:
        vps.command(["systemctl", "daemon-reload"], timeout=35)
    if remove_swap:
        SWAP.unlink()
        vps.syncdir(SWAP.parent)
    for key, values in reversed(list(plan["runtime"].items())):
        if kernel(key) != values["before"]:
            set_kernel(key, values["before"])
    if str(JOURNAL) in plan["files"]:
        restart_journal()
    plan["state"] = "rolled-back"
    vps.atomic_json(record, plan)


def apply(args):
    guard_host()
    with vps.lock():
        if any(p["state"] == "pending" for _, p in tune_records()):
            raise vps.Failure("存在未完成的优化，请先运行 tune rollback。")
        plan = build_plan(args)
        print_plan(plan)
        if not plan["files"] and all(v["before"] == v["after"] for v in plan["runtime"].values()):
            check_journal(plan["journal_limit"])
            print("当前状态已符合所选设置。")
            return
        folder = vps.ROOT / f"tune-{time.time_ns():019d}-{uuid.uuid4().hex[:8]}"
        folder.mkdir(mode=0o700)
        record = folder / "tuning.json"
        plan["state"] = "pending"
        plan["boot_id"] = boot_id()
        vps.atomic_json(record, plan)
        print(f"回退记录 {folder.name}", flush=True)
        try:
            if plan["swap_mib"]:
                create_swap(plan, record)
            if args.bbr and "bbr" not in kernel(ALGORITHMS).split():
                vps.command(["modprobe", "tcp_bbr"])
                if "bbr" not in kernel(ALGORITHMS).split():
                    raise vps.Failure("当前内核未提供可用的 BBR。")
            for name, values in plan["files"].items():
                path = Path(name)
                if read(path) != values["before"]:
                    raise vps.Failure(f"{path} 在预检后已变化。")
                write(path, values["after"])
            if str(FSTAB) in plan["files"]:
                vps.command(["systemctl", "daemon-reload"], timeout=35)
            for key, values in plan["runtime"].items():
                if kernel(key) != values["after"]:
                    set_kernel(key, values["after"])
            check_journal(plan["journal_limit"])
            if str(JOURNAL) in plan["files"]:
                restart_journal()
            plan["state"] = "applied"
            vps.atomic_json(record, plan)
            print("已应用并检查当前状态。下次重启后运行 sudo rayzento tune verify --after-reboot。")
        except BaseException:
            try:
                restore(record, plan)
            except (OSError, vps.Failure, ValueError) as error:
                print(f"回退未完成：{error}。记录 {folder.name}")
            raise


def rollback(transaction):
    guard_host()
    with vps.lock():
        latest = next(((record, plan) for record, plan in tune_records() if plan["state"] != "rolled-back"), None)
        if not latest:
            raise vps.Failure("没有可回退的优化。")
        record, plan = latest
        if transaction and record.parent.name != transaction:
            raise vps.Failure(f"请先回退较新的记录 {record.parent.name}。")
        restore(record, plan)
        print(f"已恢复 {record.parent.name} 的原配置和可回退的运行值。")


def status():
    for args in (["free", "-h"], ["swapon", "--show"], ["df", "-h", "/"], ["journalctl", "--disk-usage"]):
        print(output(args))
    entries = fstab_swap(read(FSTAB) or "")
    print(f"fstab Swap: {', '.join(entries) or '无'}")
    options = journal_options()
    print(f"Journald: Storage={options.get('Storage', 'auto')} SystemMaxUse={options.get('SystemMaxUse', '默认')}")
    for key in (SWAPPINESS, ALGORITHMS, QDISC, BBR):
        print(f"{key}={kernel(key)}")
    print(f"tcp_bbr 模块: {'已加载' if Path('/sys/module/tcp_bbr').exists() else '未见加载'}")
    print(output(["tc", "qdisc", "show"]))


def verify(after_reboot):
    plans = [plan for _, plan in tune_records() if plan["state"] != "rolled-back"]
    if not plans or any(plan["state"] == "pending" for plan in plans):
        raise vps.Failure("需要一笔已完成且没有待回退的优化记录。")
    if after_reboot and plans[0]["boot_id"] == boot_id():
        raise vps.Failure("最后一次应用之后尚未重启。")
    runtime, files = {}, {}
    for plan in reversed(plans):
        runtime.update(plan["runtime"])
        files.update(plan["files"])
    for name, values in files.items():
        if read(Path(name)) != values["after"]:
            raise vps.Failure(f"持久化文件与记录不一致：{name}")
    for key, values in runtime.items():
        if kernel(key) != values["after"]:
            raise vps.Failure(f"运行值与记录不一致：{key}")
    if any(plan["swap_inode"] for plan in plans):
        if str(SWAP) not in active_swap() or fstab_swap(read(FSTAB) or "").count(str(SWAP)) != 1:
            raise vps.Failure("未找到活动的 RayZento Swap 或唯一的 fstab 条目。")
    if BBR in runtime and "bbr" not in kernel(ALGORITHMS).split():
        raise vps.Failure("当前内核未提供可用的 BBR。")
    check_journal(plans[0]["journal_limit"])
    vps.command(["systemctl", "is-active", "--quiet", "systemd-journald.service"])
    print("优化配置和当前运行值检查通过。")


def bounded(value, low, high):
    n = int(value)
    if not low <= n <= high:
        raise argparse.ArgumentTypeError(f"允许范围 {low}–{high}。")
    return n


def add_commands(parser):
    actions = parser.add_subparsers(dest="tune_action", required=True)
    actions.add_parser("status", help="查看内存、Swap、根分区、Journal 和实际 BBR/qdisc")
    for name, help_text in (("plan", "只读预览"), ("apply", "应用并保存回退记录")):
        sub = actions.add_parser(name, help=help_text)
        sub.add_argument("--swap-mib", type=lambda s: bounded(s, 0, 4096), default=1024, help="默认 1024，0 表示跳过创建")
        sub.add_argument("--swappiness", type=lambda s: bounded(s, 0, 200), default=20)
        sub.add_argument("--journal-mib", type=lambda s: bounded(s, 16, 1024), default=100)
        sub.add_argument("--bbr", action="store_true", help="另行启用当前内核的 BBR 和 fq 默认队列")
    actions.add_parser("rollback", help="回退最近一笔优化").add_argument("transaction", nargs="?")
    check = actions.add_parser("verify", help="验证持久化配置和运行状态")
    check.add_argument("--after-reboot", action="store_true", help="要求最后一次应用后已重启")
    oom = actions.add_parser("oom", help="查询内核 OOM 日志")
    oom.add_argument("--previous", action="store_true", help="查看上一次启动")
    vacuum = actions.add_parser("vacuum", help="永久清理归档 Journal")
    vacuum.add_argument("--mib", type=lambda s: bounded(s, 16, 1024), default=100)
    vacuum.add_argument("--rotate", action="store_true", help="先轮转，使此前的活动日志也可进入清理范围")


def run(args):
    action = args.tune_action
    if action == "status":
        status()
    elif action == "plan":
        guard_host()
        print_plan(build_plan(args))
    elif action == "apply":
        apply(args)
    elif action == "rollback":
        rollback(args.transaction)
    elif action == "verify":
        verify(args.after_reboot)
    elif action == "oom":
        p = vps.command(["journalctl", "-k", "-b", "-1" if args.previous else "0",
                         "--no-pager", "--case-sensitive=no", "--grep=oom|out of memory|killed process", "-n", "100"],
                        check=False)
        print(p.stdout.decode(errors="replace").strip() or "该启动记录没有匹配的 OOM 日志。")
        if p.stderr:
            print(p.stderr.decode(errors="replace").strip())
        if p.returncode not in (0, 1):
            raise vps.Failure("读取内核日志失败。")
    else:
        with vps.lock():
            cmd = ["journalctl", f"--vacuum-size={args.mib}M"]
            if args.rotate:
                cmd.append("--rotate")
            vps.command(cmd, timeout=90)
            print(output(["journalctl", "--disk-usage"]))
