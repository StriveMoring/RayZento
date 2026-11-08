"""Restricted service, node and backup management."""
import copy
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import sys
import time
import uuid

import homegateway_vps as vps
import homegateway_provision as provision
import rayzento_nodes as nodes

CHANGE_ID = re.compile(r"change-[0-9]{19}-[0-9a-f]{8}")
REMOVED_ID = re.compile(r"removed-[0-9]{19}-[0-9a-f]{8}")


def installed():
    return [c for c in vps.ORDER if (vps.OPT / c / "origin.json").is_file()]


def config_inbounds(core, config):
    return config["listeners" if core == "mihomo" else "inbounds"]


def config_ports(core, config):
    return sorted({f"{proto} {entry.get('listen', '0.0.0.0')}:{entry['port' if core != 'sing-box' else 'listen_port']}"
                   for entry in config_inbounds(core, config)
                   for proto in provision.NAMES[entry["name" if core == "mihomo" else "tag"]][2]})


def load_config(core):
    path = vps.OPT / core / "server.json"
    vps.root_owned_path(path)
    if path.is_symlink():
        raise vps.Failure("配置文件是符号链接。")
    return json.loads(path.read_text())


def service(core, action):
    with vps.lock():
        svc = vps.inspect(core, require_running=False)
        cfg = load_config(core)
        if action in ("start", "restart"):
            if not config_inbounds(core, cfg):
                raise vps.Failure("该核心没有节点，请先添加节点。")
            vps.command(vps.config_check(core, svc.exe, svc.config), timeout=35)
            if action == "start" and svc.pid:
                print("核心已经运行。")
                return
            vps.boot(svc.unit, svc.exe, config_ports(core, cfg), vps.sha(svc.exe))
        elif action == "stop":
            vps.command(["systemctl", "stop", svc.unit], timeout=40)
            if vps.sysprop(svc.unit, "MainPID") not in ("", "0"):
                raise vps.Failure("核心尚未停止。")
        elif action in ("enable", "disable"):
            if action == "enable" and not config_inbounds(core, cfg):
                raise vps.Failure("该核心没有节点。")
            vps.command(["systemctl", action, svc.unit])
        elif action == "logs":
            print(vps.command(["journalctl", "-u", svc.unit, "-n", "80", "--no-pager", "-o", "short-iso"]).stdout.decode(errors="replace"))
        else:
            raise vps.Failure("未知服务操作。")
        print(f"{svc.unit} {vps.sysprop(svc.unit, 'ActiveState')} / 自启 {vps.sysprop(svc.unit, 'UnitFileState')}")


def list_backups():
    rows = []
    if not vps.ROOT.exists():
        return rows
    for folder in vps.ROOT.iterdir():
        if folder.is_symlink() or not folder.is_dir():
            continue
        if vps.TXID.fullmatch(folder.name):
            filename, label = "manifest.json", "核心升级"
        elif CHANGE_ID.fullmatch(folder.name):
            filename, label = "change.json", "节点配置"
        elif REMOVED_ID.fullmatch(folder.name):
            filename, label = "removal.json", "核心卸载"
        else:
            continue
        path = folder / filename
        if path.is_symlink() or not path.is_file():
            continue
        vps.root_owned_path(path)
        data = json.loads(path.read_text())
        if data["state"] == "rolled-back":
            continue
        created = backup_time(folder.name)
        rows.append((folder.name, f"{created.isoformat(timespec='seconds')} · {label} · {data['state']}"))
    return sorted(rows, key=lambda row: backup_time(row[0]), reverse=True)


def backup_time(txid):
    if vps.TXID.fullmatch(txid):
        return datetime.datetime.strptime(txid[:16], "%Y%m%dT%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
    nanoseconds = int(txid.split("-")[1])
    return datetime.datetime.fromtimestamp(nanoseconds / 1_000_000_000, datetime.timezone.utc)


def check_pending():
    for txid, _ in list_backups():
        if CHANGE_ID.fullmatch(txid) or REMOVED_ID.fullmatch(txid):
            filename = "change.json" if CHANGE_ID.fullmatch(txid) else "removal.json"
            state = json.loads((vps.ROOT / txid / filename).read_text())["state"]
            if state in ("pending", "rollback-incomplete"):
                raise vps.Failure(f"先回退未完成的节点操作 {txid}。")


def commit(core, config, inventory, reason, *, expected_config=None, expected_nodes=None):
    with vps.lock():
        check_pending()
        svc = vps.inspect(core, require_running=False)
        before_config, before_nodes = load_config(core), nodes.load(core)
        if ((expected_config is not None and expected_config != before_config)
                or (expected_nodes is not None and expected_nodes != before_nodes)):
            raise vps.Failure("节点在准备期间已变化，请重新打开节点菜单。")
        folder = vps.ROOT / f"change-{time.time_ns():019d}-{uuid.uuid4().hex[:8]}"
        folder.mkdir(mode=0o700)
        candidate = folder / "candidate.json"
        vps.atomic_json(candidate, config)
        vps.command(vps.config_check(core, svc.exe, candidate), timeout=35)
        data = {"core": core, "reason": reason, "binary_sha": vps.sha(svc.exe),
                "active": bool(svc.pid), "enabled": vps.sysprop(svc.unit, "UnitFileState") == "enabled",
                "before_config": before_config, "after_config": config,
                "before_nodes": before_nodes, "after_nodes": inventory, "state": "pending"}
        vps.atomic_json(folder / "change.json", data)
        print(f"节点回退记录 {folder.name}")
        try:
            vps.atomic_json(svc.config, config)
            vps.atomic_json(vps.OPT / core / "nodes.json", inventory)
            if config_inbounds(core, config):
                first_node = not config_inbounds(core, before_config)
                if data["active"] or first_node:
                    vps.boot(svc.unit, svc.exe, config_ports(core, config), data["binary_sha"])
                if first_node:
                    vps.command(["systemctl", "enable", svc.unit])
            else:
                vps.command(["systemctl", "disable", "--now", svc.unit], timeout=40)
                if vps.sysprop(svc.unit, "MainPID") not in ("0", ""):
                    raise vps.Failure("空节点核心尚未停止。")
            data["state"] = "applied"
            vps.atomic_json(folder / "change.json", data)
        except BaseException:
            try:
                restore_change(folder, data)
            except Exception as error:
                data["state"] = "rollback-incomplete"
                vps.atomic_json(folder / "change.json", data)
                print(f"自动回退未完成 {error}")
            raise
    nodes.export()


def restore_change(folder, data):
    core = data["core"]
    svc = vps.inspect(core, require_running=False)
    if vps.sha(svc.exe) != data["binary_sha"]:
        raise vps.Failure("核心版本已变化，请先处理之后的升级。")
    if load_config(core) not in (data["before_config"], data["after_config"]) or nodes.load(core) not in (data["before_nodes"], data["after_nodes"]):
        raise vps.Failure("节点配置已变化，请先回退较新的节点操作。")
    vps.atomic_json(folder / "restore.json", data["before_config"])
    vps.command(vps.config_check(core, svc.exe, folder / "restore.json"), timeout=35)
    vps.atomic_json(svc.config, data["before_config"])
    vps.atomic_json(vps.OPT / core / "nodes.json", data["before_nodes"])
    if data["active"]:
        vps.boot(svc.unit, svc.exe, config_ports(core, data["before_config"]), data["binary_sha"])
    else:
        vps.command(["systemctl", "stop", svc.unit], timeout=40)
    vps.command(["systemctl", "enable" if data["enabled"] else "disable", svc.unit])
    data["state"] = "rolled-back"
    vps.atomic_json(folder / "change.json", data)


def change_node(profile, *, port=None, delete=False, server=None, client_port=None):
    core = provision.NAMES[profile][0]
    config, inventory = load_config(core), nodes.load(core)
    expected_config, expected_nodes = copy.deepcopy(config), copy.deepcopy(inventory)
    item = next((node for node in inventory if node["profile"] == profile), None)
    if item is None:
        raise vps.Failure("该协议节点不存在。")
    entry = next(e for e in config_inbounds(core, config) if e["name" if core == "mihomo" else "tag"] == profile)
    if delete:
        config_inbounds(core, config).remove(entry)
        inventory.remove(item)
    if port is not None:
        current = entry["listen_port" if core == "sing-box" else "port"]
        if port == current:
            return
        provision.port_plan(None, [f"{profile}={port}"], provision.listening_ports())
        entry["listen_port" if core == "sing-box" else "port"] = port
        item["client"]["port"] = port
    if server is not None:
        item["client"]["server"] = nodes.public_host(server)
    if client_port is not None:
        if not 1 <= client_port <= 65535:
            raise vps.Failure("客户端公网端口需要 1–65535。")
        item["client"]["port"] = client_port
    commit(core, config, inventory, "删除节点" if delete else "修改节点",
           expected_config=expected_config, expected_nodes=expected_nodes)


def add_node(profile, server, cert=None, key=None, sni=None, port="auto"):
    core = provision.NAMES[profile][0]
    svc = vps.inspect(core, require_running=False)
    config, inventory = load_config(core), nodes.load(core)
    expected_config, expected_nodes = copy.deepcopy(config), copy.deepcopy(inventory)
    if any(n["profile"] == profile for n in inventory):
        raise vps.Failure("该协议节点已经存在。")
    ports = provision.port_plan(None, [f"{profile}={port}"], provision.listening_ports() | {
        int(n["client"]["port"]) for n in nodes.all_nodes()})
    if profile in provision.TLS:
        if not cert or not key or not sni:
            raise vps.Failure("该协议需要证书。")
        provision.tls_check(cert, key, sni)
    configs, clients, links = provision.profiles(ports, server, sni or server, "apple.com", "0.0.0.0",
                                               cert, key, {core: svc.exe})
    config_inbounds(core, config).extend(config_inbounds(core, configs[core]))
    inventory.extend(nodes.records(ports, clients, links))
    commit(core, config, inventory, "添加节点", expected_config=expected_config, expected_nodes=expected_nodes)


def remove_core(core):
    with vps.lock():
        check_pending()
        svc = vps.inspect(core, require_running=False)
        folder = vps.ROOT / f"removed-{time.time_ns():019d}-{uuid.uuid4().hex[:8]}"
        folder.mkdir(mode=0o700)
        unit = vps.UNITS / svc.unit
        data = {"core": core, "active": bool(svc.pid), "enabled": vps.sysprop(svc.unit, "UnitFileState") == "enabled",
                "unit": unit.read_text(), "binary_sha": vps.sha(svc.exe), "state": "pending"}
        vps.atomic_json(folder / "removal.json", data)
        try:
            vps.command(["systemctl", "disable", "--now", svc.unit], timeout=40)
            if vps.sysprop(svc.unit, "MainPID") not in ("", "0"):
                raise vps.Failure("核心尚未停止，保留所有文件。")
            shutil.move(str(vps.OPT / core), folder / core)
            unit.unlink()
            vps.command(["systemctl", "daemon-reload"])
            data["state"] = "removed"
            vps.atomic_json(folder / "removal.json", data)
        except BaseException:
            restore_removal(folder, data)
            raise
        print(f"{core} 已卸载，私有回退记录 {folder.name}")
    nodes.export()


def restore_removal(folder, data):
    core = data["core"]
    unit_name = vps.SPECS[core][1]
    target, saved = vps.OPT / core, folder / core
    unit = vps.UNITS / unit_name
    if saved.exists():
        if target.exists() or unit.is_symlink() or (unit.exists() and unit.read_text() != data["unit"]):
            raise vps.Failure("该核心已重新安装，保留当前版本。")
        if vps.sha(saved / core) != data["binary_sha"]:
            raise vps.Failure("卸载备份的二进制已变化。")
        shutil.move(str(saved), target)
    if not target.exists():
        raise vps.Failure("未找到可恢复的核心目录。")
    if unit.is_symlink() or (unit.exists() and unit.read_text() != data["unit"]):
        raise vps.Failure("同名服务文件已变化。")
    unit.write_text(data["unit"])
    unit.chmod(0o644)
    vps.command(["systemctl", "daemon-reload"])
    vps.command(["systemctl", "enable" if data["enabled"] else "disable", unit_name])
    if data["active"]:
        cfg = load_config(core)
        vps.command(vps.config_check(core, target / core, target / "server.json"), timeout=35)
        vps.boot(unit_name, target / core, config_ports(core, cfg), data["binary_sha"])
    else:
        vps.command(["systemctl", "stop", unit_name], timeout=40)
    data["state"] = "rolled-back"
    vps.atomic_json(folder / "removal.json", data)


def rollback(txid):
    if vps.TXID.fullmatch(txid):
        vps.rollback(txid)
        return
    with vps.lock():
        folder = vps.ROOT / txid
        if CHANGE_ID.fullmatch(txid):
            path = folder / "change.json"
            restore = restore_change
        elif REMOVED_ID.fullmatch(txid):
            path = folder / "removal.json"
            restore = restore_removal
        else:
            raise vps.Failure("备份编号不符。")
        if folder.is_symlink() or path.is_symlink():
            raise vps.Failure("备份是符号链接。")
        vps.root_owned_path(path)
        data = json.loads(path.read_text())
        if data["core"] not in vps.SPECS:
            raise vps.Failure("备份核心名称不符。")
        restore(folder, data)
    nodes.export()
    print("备份已恢复。")


def remove_manager():
    import rayzento_certificates as certificates
    with vps.lock():
        if installed():
            raise vps.Failure("请先卸载全部核心。")
        target = Path("/usr/local/bin/rayzento")
        if target.is_symlink() or target.resolve() != Path(sys.argv[0]).resolve():
            raise vps.Failure("请从已注册的 rayzento 执行卸载管理器。")
        vps.root_owned_path(target)
        hook = certificates.HOOK
        if hook.exists() or hook.is_symlink():
            if hook.is_symlink() or "# Managed by RayZento" not in hook.read_text():
                raise vps.Failure("证书 hook 内容已变化，请先核对。")
            vps.root_owned_path(hook)
            hook.unlink()
        target.unlink()
        vps.syncdir(target.parent)
    print(f"管理器已卸载。私有备份保留在 {vps.ROOT}，系统优化可用发布文件单独回退。")
