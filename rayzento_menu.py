"""Numeric RayZento management menus."""
import os
import json
from pathlib import Path
import shutil
import sys
import tempfile
import zipfile

import rayzento_provision as provision
import rayzento_core as vps
import rayzento_certificates as certificates
import rayzento_manage as manage
import rayzento_nodes as nodes
import rayzento_update as updates


MAIN = (
    "安装或添加节点", "节点资料与管理", "核心服务管理", "核心升级",
    "小内存 VPS 优化", "证书申请与续期", "备份与回退", "更新 RayZento",
    "检查 VPS 兼容性", "查看协议和预设", "注册 rayzento 管理命令", "卸载核心或全部节点",
)
COMMAND_PATH = Path("/usr/local/bin/rayzento")


def choose(title, items, exit_text="返回"):
    while True:
        print(f"\n{title}")
        for number, item in enumerate(items, 1):
            print(f"  {number}. {item}")
        print(f"  0. {exit_text}")
        answer = input("选择编号 > ").strip()
        if answer.isascii() and answer.isdecimal() and len(answer) <= 3:
            choice = int(answer)
            if 0 <= choice <= len(items):
                return choice
        print("请输入列表里的编号。")


def confirm(message):
    return choose(message, ("确认",), "取消") == 1


def required(prompt):
    while True:
        value = input(f"{prompt} > ").strip()
        if value:
            return value
        print("请填写内容，或按 Ctrl+C 返回。")


def defaults(prompt, value):
    return input(f"{prompt} [{value}] > ").strip() or value


def execute(argv):
    vps.main(argv)


def operation(handler):
    try:
        return handler()
    except EOFError:
        raise
    except KeyboardInterrupt:
        print("\n操作已取消或中断。")
    except SystemExit as error:
        if error.code not in (None, 0):
            print(f"操作停止，退出码 {error.code}。")
    except vps.ACTION_ERRORS as error:
        print(f"操作失败：{error}", file=sys.stderr)


def submenu(title, items, handlers, *, return_after_success=False):
    while True:
        choice = choose(title, items)
        if not choice:
            return
        result = operation(handlers[choice - 1])
        if return_after_success and result is True:
            return


def settings():
    path = vps.ROOT / "install-defaults.json"
    if not path.exists():
        return {}
    if path.is_symlink():
        raise vps.Failure("默认配置是符号链接。")
    vps.root_owned_path(path)
    return json.loads(path.read_text())


def save_settings(data):
    with vps.lock():
        vps.atomic_json(vps.ROOT / "install-defaults.json", data)


def server_address():
    known = settings().get("server")
    if known:
        return nodes.public_host(known)
    try:
        return nodes.detect_address()
    except vps.Failure as error:
        print(error)
        return nodes.public_host(required("VPS 公网入口 IPv4 或域名"))


def tls_details(server):
    saved = settings()
    if all(saved.get(k) for k in ("certificate", "key", "sni")):
        try:
            cert, key = Path(saved["certificate"]), Path(saved["key"])
            provision.tls_check(cert, key, saved["sni"])
            return saved["sni"], cert, key
        except (vps.Failure, OSError, ValueError):
            print("已保存证书未通过检查，重新选择证书。")
    existing = certificates.managed()
    if existing:
        hostname = existing[0]["domain"]
    else:
        print("TLS 入站将自动申请 Let's Encrypt 证书并同意其服务条款。")
        print("请准备指向本机的域名，公网 TCP 80 需允许访问。")
        hostname = required("证书域名，输入一次")
    cert, key = certificates.issue(hostname, server)
    return hostname, cert, key


def install_selected(names, options):
    vps.host_check()
    current = {n["profile"] for n in nodes.all_nodes()}
    selected = [n for n in names if n not in current]
    if not selected:
        print("所选协议已安装，可在节点管理中修改。")
        return True
    options = {k: value for k, value in options.items() if k in selected}
    server = server_address()
    sni, cert, key = server, None, None
    if provision.TLS.intersection(selected):
        sni, cert, key = tls_details(server)
    print("安装所选协议，自动生成凭据和空闲端口。REALITY 导出使用 Chrome，Xray 节点含 Mihomo ML-KEM 参数。")
    fresh = []
    for name in selected:
        core = provision.NAMES[name][0]
        if core in manage.installed():
            manage.add_node(name, server, cert, key, sni, options.get(name, "auto"))
        else:
            fresh.append(name)
    if fresh:
        argv = ["install", "--server", server, "--reality-client-ready"]
        for name in fresh:
            argv += ["--profile", f"{name}={options.get(name, 'auto')}"]
        if cert:
            argv += ["--sni", sni, "--certificate", str(cert), "--key", str(key)]
        execute(argv)
    saved = {"server": server}
    if cert:
        saved.update(sni=sni, certificate=str(cert), key=str(key))
    save_settings(saved)
    if not fresh:
        nodes.display()
        nodes.export()
    print("安装完成，返回主菜单。")
    return True


def custom_install():
    profiles = list(provision.NAMES)
    selected = {}
    while True:
        labels = [f"{'[已选] ' if p in selected else ''}{p} · {provision.NAMES[p][1]}" for p in profiles]
        choice = choose("自选协议，编号固定；再次选择可取消", [*labels, "开始安装"], "取消")
        if not choice:
            return
        if choice == len(profiles) + 1:
            if selected:
                return install_selected(list(selected), selected)
            print("请先选择至少一个协议。")
            continue
        name = profiles[choice - 1]
        if name in selected:
            del selected[name]
        else:
            selected[name] = defaults("端口，回车自动分配", "auto")


def install_nodes():
    submenu("安装组合，选择预设后自动安装", (
        "最小组合，Xray VLESS REALITY", "标准组合，Xray REALITY、AnyTLS、TUIC",
        "完整组合，Xray 和 sing-box 的 10 种入站", "自选协议和端口",
    ), (
        lambda: install_selected(["vless-reality"], {}),
        lambda: install_selected(list(provision.PRESETS["standard"]), {}),
        lambda: install_selected(list(provision.PRESETS["full"]), {}),
        custom_install,
    ), return_after_success=True)


def select_node():
    inventory = nodes.all_nodes()
    if not inventory:
        print("当前没有节点。")
        return None
    choice = choose("选择节点", [f"{n['profile']} · {n['client']['server']}:{n['client']['port']}" for n in inventory])
    return inventory[choice - 1] if choice else None


def edit_node(action):
    vps.host_check()
    node = select_node()
    if node is None:
        return
    profile, client = node["profile"], node["client"]
    if action == "port":
        raw = defaults("新的监听端口", str(client["port"]))
        port = int(raw)
        if confirm(f"将 {profile} 的端口改为 {port}，相关核心会重启"):
            manage.change_node(profile, port=port)
    elif action == "endpoint":
        server = defaults("客户端公网入口 IPv4 或域名", client["server"])
        port = int(defaults("客户端公网端口，NAT 映射时填外部端口", str(client["port"])))
        if confirm("更新该节点客户端入口"):
            manage.change_node(profile, server=server, client_port=port)
    elif action == "delete" and confirm(f"永久删除有效节点 {profile}，保留私有回退备份"):
        manage.change_node(profile, delete=True)


def node_menu():
    vps.host_check()
    submenu("节点资料与管理", ("显示全部节点链接", "导出客户端文件", "修改节点监听端口",
                              "修改客户端公网入口", "删除节点"),
            (nodes.display, nodes.export, lambda: edit_node("port"), lambda: edit_node("endpoint"), lambda: edit_node("delete")))


def select_core():
    cores = manage.installed()
    if not cores:
        print("当前未安装核心。")
        return None
    choice = choose("选择核心", cores)
    return cores[choice - 1] if choice else None


def service_action(action):
    vps.host_check()
    core = select_core()
    if core and (action == "logs" or confirm(f"对 {core} 执行 {action}")):
        manage.service(core, action)


def service_menu():
    submenu("核心服务管理", ("查看状态", "启动", "停止", "重启", "开启开机自启", "关闭开机自启", "查看最近日志"),
            (lambda: execute(["audit"]), *(lambda a=a: service_action(a) for a in ("start", "stop", "restart", "enable", "disable", "logs"))))


def upgrade_cores():
    vps.host_check()
    cores = manage.installed()
    if not cores:
        print("当前未安装核心。")
        return
    choice = choose("选择要检查的核心", [*cores, "全部已安装核心"])
    if not choice:
        return
    targets = cores if choice == len(cores) + 1 else [cores[choice - 1]]
    pins, needs_reality = [], False
    for core in targets:
        service = vps.inspect(core)
        tag = vps.version(vps.release(core)["tag_name"])
        if vps.tag_numbers(tag) < vps.tag_numbers(service.old):
            raise vps.Failure(f"{core} 的官方正式版低于当前版本。")
        pins += [f"--{core}-version", tag]
        needs_reality |= tag != service.old and vps.requires_reality_preflight(service, tag)
    execute(["plan", *pins])
    if not confirm("确认升级，相关核心会短暂重启"):
        return
    if needs_reality:
        print("新 Xray REALITY 节点需核对 Chrome 和 ML-KEM。")
        if not confirm("确认已核对现有客户端"):
            return
        pins.append("--reality-client-ready")
    execute(["upgrade", *pins])


def core_menu():
    submenu("核心升级", ("查看官方正式版", "预览并升级"), (lambda: execute(["releases"]), upgrade_cores))


def tune_apply():
    vps.host_check()
    args = ["--swap-mib", defaults("Swap MiB，0 跳过创建", "1024"),
            "--swappiness", defaults("swappiness", "20"),
            "--journal-mib", defaults("持久日志预算 MiB", "100")]
    if confirm("同时启用 BBR + FQ"):
        args.append("--bbr")
    execute(["tune", "plan", *args])
    if confirm("确认应用优化"):
        execute(["tune", "apply", *args])


def vacuum():
    vps.host_check()
    size = defaults("归档日志预算 MiB", "100")
    if confirm("确认永久删除超出预算的归档日志"):
        execute(["tune", "vacuum", "--mib", size])


def tune_menu():
    submenu("小内存 VPS 优化", ("查看状态", "预览并应用", "验证当前设置", "验证重启后设置",
                              "查看上次 OOM", "清理归档日志", "回退最近一次优化"),
            (lambda: execute(["tune", "status"]), tune_apply, lambda: execute(["tune", "verify"]),
             lambda: execute(["tune", "verify", "--after-reboot"]), lambda: execute(["tune", "oom", "--previous"]),
             vacuum, lambda: execute(["tune", "rollback"]) if confirm("确认回退优化") else None))


def rollback_menu():
    vps.host_check()
    entries = manage.list_backups()
    if not entries:
        print("当前没有可回退备份。")
        return
    choice = choose("选择备份，优先回退较新的变更", [label for _, label in entries])
    if choice and confirm("确认恢复所选备份，相关核心可能短暂重启"):
        manage.rollback(entries[choice - 1][0])


def import_certificate():
    vps.host_check()
    server = server_address()
    hostname = certificates.domain(required("证书域名"))
    cert = Path(required("证书文件绝对路径")).resolve(strict=True)
    key = Path(required("私钥文件绝对路径")).resolve(strict=True)
    provision.tls_check(cert, key, hostname)
    save_settings({"server": server, "sni": hostname, "certificate": str(cert), "key": str(key)})
    print("证书已作为后续安装默认值。自有证书由原签发工具续期。")


def issue_certificate():
    vps.host_check()
    hostname = required("证书域名，DNS 指向本机且 TCP 80 放行")
    if confirm("通过 Let's Encrypt 申请并接受其服务条款"):
        server = server_address()
        cert, key = certificates.issue(hostname, server)
        save_settings({"server": server, "sni": hostname, "certificate": str(cert), "key": str(key)})


def certificate_menu():
    vps.host_check()
    submenu("证书管理", ("查看证书与续期任务", "自动申请证书", "导入已有证书", "检查续期", "模拟续期验收"),
            (certificates.status, issue_certificate, import_certificate,
             certificates.renew, lambda: certificates.renew(dry_run=True)))


def update_menu():
    vps.host_check()
    choice = choose("RayZento 管理器更新", ("检查并更新", "恢复上一版脚本"))
    if choice == 1:
        candidate = updates.preview()
        if confirm("确认下载并更新管理器"):
            if updates.update(candidate):
                return True
    elif choice == 2 and confirm("确认恢复上一版管理器"):
        updates.rollback()
        return True
    return False


def uninstall():
    vps.host_check()
    cores = manage.installed()
    choice = choose("卸载范围，备份保存在私有目录", [*cores, "全部核心和节点", "卸载 RayZento 管理器（先卸载全部核心）"])
    if choice == len(cores) + 2:
        if confirm("确认卸载管理器，保留私有备份"):
            manage.remove_manager()
            return True
        return False
    if choice and confirm("确认停止并卸载所选核心，客户端连接会中断"):
        selected = cores if choice == len(cores) + 1 else [cores[choice - 1]]
        for core in selected:
            manage.remove_core(core)
        print("所选核心已卸载。备份、证书和系统优化可分别在对应菜单管理。")

def register_command(*, confirmed=False):
    vps.host_check()
    source = Path(sys.argv[0]).resolve(strict=True)
    target = COMMAND_PATH
    required_members = {"__main__.py", "rayzento_menu.py", "rayzento-release.json"}
    with zipfile.ZipFile(source) as archive:
        if not required_members <= set(archive.namelist()):
            raise vps.Failure("请从发布包中的单文件 rayzento 运行注册。")
    if target.is_symlink():
        raise vps.Failure("现有 rayzento 命令是符号链接。")
    if target.exists():
        vps.root_owned_path(target)
        try:
            with zipfile.ZipFile(target) as archive:
                if not required_members <= set(archive.namelist()):
                    raise zipfile.BadZipFile
        except zipfile.BadZipFile:
            raise vps.Failure("已存在同名命令，无法确认是 RayZento。") from None
        if source == target:
            print(f"管理命令已注册在 {target}。")
            return
    if not confirmed and not confirm(f"注册管理命令到 {target}"):
        return
    vps.root_owned_path(target.parent)
    with tempfile.NamedTemporaryFile(prefix=".rayzento-", dir=target.parent, delete=False) as dest:
        staged = Path(dest.name)
        try:
            with source.open("rb") as original:
                shutil.copyfileobj(original, dest)
            os.fchmod(dest.fileno(), 0o755)
            dest.flush()
            os.fsync(dest.fileno())
            os.replace(staged, target)
            vps.syncdir(target.parent)
        finally:
            staged.unlink(missing_ok=True)
    print("管理命令已注册。以后运行 sudo rayzento。")




def run():
    handlers = (install_nodes, node_menu, service_menu, core_menu, tune_menu, certificate_menu,
                rollback_menu, update_menu, lambda: execute(["doctor"]), lambda: execute(["profiles"]),
                register_command, uninstall)
    while True:
        try:
            action = choose(f"RayZento {vps.VERSION}\n管理命令：rayzento（非 root 用户：sudo rayzento）", MAIN, "退出")
            if action == 0:
                return
            result = operation(handlers[action - 1])
            if action in (8, 12) and result:
                return
        except (EOFError, KeyboardInterrupt):
            print()
            return
