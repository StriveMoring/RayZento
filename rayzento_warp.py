"""IPv4 WARP for all RayZento Xray and sing-box client traffic."""

import base64
import configparser
import copy
from dataclasses import dataclass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import tempfile
import time
import sys
import zipfile

import rayzento_core as vps
import rayzento_manage as manage
import rayzento_terminal as terminal
from rayzento_warp_checks import compare_sites, core_probe, trace as tcp_trace, udp_exit


UNIT = 'rayzento-warp-link.service'
MONITOR_TIMER = 'rayzento-warp-monitor.timer'
MONITOR_UNIT = 'rayzento-warp-monitor.service'
DEVICE = 'rzwarp0'
TABLE = 36279
PRIORITY = 110
WGCF_VERSION = '2.3.1'
WGCF_DIGESTS = {
    'amd64': '4fb7a136aa470ece11d17949c7db07b040ec9c604742dc8680bcf1889f85d0c8',
    'arm64': '710ab2d8ac145d81a4cf0c11bdb0e05914f77ae2a45f67b87e718d84b4cb7301',
}
PHASES = {'preparing': '上次切换尚未完成准备', 'applying': '切换未完成', 'restoring': '等待完成回退'}
REGIONS = {'US': '美国', 'DE': '德国', 'HK': '香港'}


@dataclass(frozen=True)
class ExitCheck:
    original: str
    tcp: str
    udp: str
    region: str


def show_exit(check):
    region = REGIONS.get(check.region, check.region)
    print(f'  WARP TCP 出口   {check.tcp}（{region}）')
    print(f'  WARP UDP 出口   {check.udp}')
    print(f'  VPS 原出口      {check.original}')


def root():
    return vps.ROOT / 'warp-full'


def state_file():
    return root() / 'state.json'


def read_state():
    path = state_file()
    if not os.path.lexists(path):
        return None
    if path.is_symlink() or not path.is_file():
        raise vps.Failure('WARP 状态文件路径不安全。')
    vps.root_owned_path(path)
    return json.loads(path.read_text())


def check_key(value):
    if not re.fullmatch(r'[A-Za-z0-9+/]{43}=', value) or len(base64.b64decode(value)) != 32:
        raise vps.Failure('WireGuard 密钥格式不符合预期。')
    return value


def profile(path):
    """Consume only standard data fields. Never execute hooks from a profile."""
    vps.root_owned_path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_mode & 0o077 or path.stat().st_size > 32768:
        raise vps.Failure('WireGuard 配置须为 root 独占的普通文件。')
    cfg = configparser.ConfigParser(interpolation=None)
    try:
        cfg.read_string(path.read_text())
        local, peer = cfg['Interface'], cfg['Peer']
        if set(cfg.sections()) != {'Interface', 'Peer'} or cfg.defaults():
            raise ValueError
        if set(local) - {'privatekey','address','dns','mtu'} or set(peer) - {'publickey','allowedips','endpoint','persistentkeepalive','presharedkey'}:
            raise ValueError
        address_list = [ipaddress.ip_interface(x.strip()) for x in local['Address'].split(',')]
        addresses = [x for x in address_list if x.version == 4]
        if len(addresses) != 1 or addresses[0].network.prefixlen != 32 or not addresses[0].ip.is_private:
            raise ValueError
        allowed = {x.strip() for x in peer['AllowedIPs'].split(',')}
        if '0.0.0.0/0' not in allowed or allowed - {'0.0.0.0/0', '::/0'}:
            raise ValueError
        host, port = peer['Endpoint'].rsplit(':', 1)
        if not re.fullmatch(r'[A-Za-z0-9.-]{1,253}', host) or not 1 <= int(port) <= 65535:
            raise ValueError
        if not (host == 'engage.cloudflareclient.com' or ipaddress.IPv4Address(host).is_global):
            raise ValueError
        endpoint = socket.getaddrinfo(host, int(port), socket.AF_INET, socket.SOCK_DGRAM)[0][4][0]
        if not ipaddress.IPv4Address(endpoint).is_global:
            raise ValueError
        mtu = int(local.get('MTU', '1280'))
        if not 1280 <= mtu <= 1420:
            raise ValueError
        private = check_key(local['PrivateKey'])
        public = check_key(peer['PublicKey'])
        preshared = check_key(peer['PresharedKey']) if 'PresharedKey' in peer else None
    except (configparser.Error, KeyError, ValueError, OSError) as error:
        raise vps.Failure('不支持的 WARP WireGuard 配置。请使用 wgcf 标准 IPv4 配置。') from None
    text = (f'[Interface]\nPrivateKey = {private}\n\n[Peer]\nPublicKey = {public}\n'
            f'AllowedIPs = 0.0.0.0/0\nEndpoint = {endpoint}:{int(port)}\nPersistentKeepalive = 25\n')
    if preshared:
        text += f'PresharedKey = {preshared}\n'
    return str(addresses[0].ip), mtu, text


def install_wireguard():
    if shutil.which('wg'):
        return
    apt = ['/usr/bin/apt-get']
    env = {**os.environ, 'LC_ALL': 'C', 'DEBIAN_FRONTEND': 'noninteractive'}
    vps.command(apt + ['-o', 'APT::Update::Error-Mode=any', 'update'], timeout=150, env=env)
    args = ['--no-remove', '--no-upgrade', '--no-install-recommends', 'install', 'wireguard-tools']
    plan = vps.command(apt + ['-s', *args], env=env).stdout.decode()
    if re.search(r'^Remv |^Inst \S+ \[', plan, re.M):
        raise vps.Failure('安装 WireGuard 需要移除或升级现有软件包。')
    vps.command(apt + ['-y', *args], timeout=150, env=env)


def registration(accept_terms):
    work = root()
    generated = work / 'wgcf-profile.conf'
    if generated.is_file():
        return generated
    if not accept_terms:
        raise vps.Failure('首次自动申请 WARP 账户需要接受 Cloudflare 条款。也可通过 --profile 导入。')
    arch = vps.arch()
    filename = f'wgcf_{WGCF_VERSION}_linux_{arch}'
    url = f'https://github.com/ViRb3/wgcf/releases/download/v{WGCF_VERSION}/{filename}'
    helper = work / 'wgcf'
    if not helper.is_file() or vps.sha(helper) != WGCF_DIGESTS[arch]:
        blob = vps.fetch(url, 32 * 1024 * 1024)
        if hashlib.sha256(blob).hexdigest() != WGCF_DIGESTS[arch]:
            raise vps.Failure('wgcf 上游文件的 SHA-256 与预期不一致。')
        temp = work / '.wgcf-new'
        if os.path.lexists(temp):
            raise vps.Failure('发现未完成的 wgcf 下载。')
        with temp.open('xb') as file:
            file.write(blob)
            os.fchmod(file.fileno(), 0o700)
        os.replace(temp, helper)
    if not (work / 'wgcf-account.toml').is_file():
        vps.command([helper, 'register', '--accept-tos'], cwd=work,
                    input=b'', timeout=45)
    vps.command([helper, 'generate'], cwd=work, timeout=30)
    generated.chmod(0o600)
    return generated


def patch_config(core, config, address):
    result = copy.deepcopy(config)
    outbounds = result.get('outbounds', [])
    if len(outbounds) != 1:
        raise vps.Failure(f'{core} 已有自定义出站，无法确认全量接管。')
    outbound = outbounds[0]
    if core == 'xray':
        settings = outbound.get('settings', {})
        blocked_v6 = any(r.get('action') == 'block' and '::/0' in r.get('ip', [])
                         for r in settings.get('finalRules', []))
        if (outbound.get('protocol') != 'freedom' or outbound.get('sendThrough')
                or outbound.get('streamSettings') or result.get('routing')
                or settings.get('domainStrategy') != 'ForceIPv4' or not blocked_v6):
            raise vps.Failure('Xray 出站不符合 RayZento 的 IPv4 直出预设。')
        outbound['sendThrough'] = address
    elif core == 'sing-box':
        route = result.get('route', {})
        blocked_v6 = any(r.get('action') == 'reject' and '::/0' in r.get('ip_cidr', [])
                         for r in route.get('rules', []))
        if outbound != {'type': 'direct', 'tag': 'internet'} or route.get('final') != 'internet' or not blocked_v6:
            raise vps.Failure('sing-box 出站不符合 RayZento 的 IPv4 直出预设。')
        outbound['inet4_bind_address'] = address
    else:
        raise vps.Failure(f'当前无法自动接管 {core} 的出站。')
    return result


def route_json(*args, check=True):
    result = vps.command(['ip', '-j', '-4', *args], check=check)
    if result.returncode and not check:
        return []
    return json.loads(result.stdout)


def check_link_free(address):
    if os.path.lexists('/run/rayzento-warp-link.owned'):
        raise vps.Failure('发现已有 WARP 网络状态，请先核对上一轮恢复。')
    if vps.command(['ip', 'link', 'show', 'dev', DEVICE], check=False).returncode == 0:
        raise vps.Failure('WARP 网卡已被占用。')
    rules = route_json('rule', 'show')
    if any(rule.get('priority') in (PRIORITY, PRIORITY + 1) or str(rule.get('table')) == str(TABLE) for rule in rules):
        raise vps.Failure('WARP 路由优先级或路由表已被占用。')
    if route_json('route', 'show', 'table', str(TABLE), check=False):
        raise vps.Failure('WARP 路由表已有配置。')
    if any(a.get('local') == address for iface in route_json('address', 'show') for a in iface.get('addr_info', [])):
        raise vps.Failure('WARP 内部地址与当前地址冲突。')
    unit = vps.UNITS / UNIT
    if os.path.lexists(unit) or vps.sysprop(UNIT, 'LoadState') not in ('not-found', ''):
        raise vps.Failure('同名 WARP systemd 服务已存在。')


def write_private(path, text):
    with path.open('x') as out:
        out.write(text)
        os.fchmod(out.fileno(), 0o600)
        out.flush()
        os.fsync(out.fileno())


def start_link(address, mtu, wg_config):
    check_link_free(address)
    wg_path = root() / 'active.conf'
    link = root() / 'link.sh'
    unit = vps.UNITS / UNIT
    ip = shutil.which('ip')
    wg = shutil.which('wg')
    if not ip or not wg or not all(re.fullmatch(r'/[A-Za-z0-9_/-]+', p) for p in (ip, wg)):
        raise vps.Failure('找不到系统 ip 或 wg 命令。')
    write_private(wg_path, wg_config)
    write_private(link, f'''#!/bin/sh
set -eu
ip={ip}
wg={wg}
dev={DEVICE}
source={address}/32
table={TABLE}
priority={PRIORITY}
owned=/run/rayzento-warp-link.owned
case "$1" in
up)
    test ! -e "$owned"
    "$ip" link add dev "$dev" type wireguard
    (umask 077; : > "$owned")
    "$wg" setconf "$dev" "{wg_path}"
    "$ip" -4 address add "$source" dev "$dev" noprefixroute
    "$ip" link set dev "$dev" mtu {mtu} up
    "$ip" -4 route add default dev "$dev" table "$table"
    "$ip" -4 rule add priority {PRIORITY + 1} from "$source" unreachable
    "$ip" -4 rule add priority "$priority" from "$source" lookup "$table"
    ;;
down)
    test -f "$owned" || exit 0
    "$ip" -4 rule del priority "$priority" from "$source" lookup "$table" 2>/dev/null || true
    "$ip" -4 rule del priority {PRIORITY + 1} from "$source" unreachable 2>/dev/null || true
    "$ip" link del dev "$dev" 2>/dev/null || true
    rm -f "$owned"
    ;;
*) exit 2 ;;
esac
''')
    unit_text = f'''[Unit]
Description=RayZento WARP IPv4 egress
Wants=network-online.target
After=network-online.target
Before=rayzento-xray.service rayzento-sing-box.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh {link} up
ExecStopPost=/bin/sh {link} down
TimeoutStartSec=20

[Install]
WantedBy=multi-user.target
'''
    write_private(unit, unit_text)
    unit.chmod(0o644)
    systemctl('daemon-reload')
    systemctl('enable', '--now', UNIT)


def systemctl(*args):
    vps.command(['/usr/bin/systemctl', *args], timeout=45)


def stop_link():
    unit = vps.UNITS / UNIT
    if unit.exists():
        vps.root_owned_path(unit)
        if unit.is_symlink() or f'ExecStart=/bin/sh {root() / "link.sh"} up' not in unit.read_text():
            raise vps.Failure('WARP 服务已改动，未删除它。')
        systemctl('disable', '--now', UNIT)
        unit.unlink()
        systemctl('daemon-reload')
    for name in ('active.conf', 'link.sh'):
        (root() / name).unlink(missing_ok=True)


def monitor_count_file():
    return root() / 'monitor-failures.json'


def monitor_running():
    if not (vps.UNITS / MONITOR_TIMER).is_file():
        return False
    return vps.sysprop(MONITOR_TIMER, 'UnitFileState') == 'enabled'


def configure_monitor(enabled):
    timer = vps.UNITS / MONITOR_TIMER
    service = vps.UNITS / MONITOR_UNIT
    package = root() / 'monitor.pyz'
    timer_text = f'''[Unit]
Description=Periodic RayZento WARP check

[Timer]
OnActiveSec=1min
OnBootSec=2min
OnUnitInactiveSec=5min
RandomizedDelaySec=25s
Unit={MONITOR_UNIT}

[Install]
WantedBy=timers.target
'''
    service_text = f'''[Unit]
Description=RayZento WARP reachability and recovery
Wants=network-online.target
After=network-online.target {UNIT}

[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {package} warp monitor
TimeoutStartSec=8min
'''
    for path, expected in ((timer, timer_text), (service, service_text)):
        if os.path.lexists(path):
            if path.is_symlink() or not path.is_file() or path.read_text() != expected:
                raise vps.Failure('发现同名监测配置，已保留原文件。')
            vps.root_owned_path(path)
    if not enabled:
        if timer.exists() and monitor_running():
            systemctl('disable', '--now', MONITOR_TIMER)
        monitor_count_file().unlink(missing_ok=True)
        return
    current = Path(sys.argv[0]).resolve()
    if not zipfile.is_zipfile(current):
        raise vps.Failure('请用打包后的 RayZento 脚本开启定时恢复。')
    with zipfile.ZipFile(current) as archive:
        if not {'__main__.py', 'rayzento_warp.py', 'rayzento_warp_checks.py'} <= set(archive.namelist()):
            raise vps.Failure('当前脚本缺少定时恢复所需模块。')
    with tempfile.NamedTemporaryFile(dir=root(), prefix='.monitor-', delete=False) as output:
        temporary = Path(output.name)
        try:
            with current.open('rb') as source:
                shutil.copyfileobj(source, output)
            output.flush()
            os.fsync(output.fileno())
            os.replace(temporary, package)
        finally:
            temporary.unlink(missing_ok=True)
    for path, expected in ((timer, timer_text), (service, service_text)):
        if not path.exists():
            write_private(path, expected)
            path.chmod(0o644)
    monitor_count_file().unlink(missing_ok=True)
    systemctl('daemon-reload')
    systemctl('enable', '--now', MONITOR_TIMER)


def monitor(state, folder):
    if not state or state['phase'] != 'enabled':
        return
    count_path = monitor_count_file()
    try:
        probe(state['address'])
    except vps.Failure as failure:
        # Check the original route first. A common WAN / probe outage is not
        # evidence that moving traffic back to native IPv4 would help.
        try:
            tcp_trace()
            udp_exit(None)
        except vps.Failure:
            count_path.unlink(missing_ok=True)
            print('原出口对照也异常，等待下一轮。')
            return
        count = int(json.loads(count_path.read_text())['count']) if count_path.is_file() else 0
        vps.atomic_json(count_path, {'count': count + 1})
        print(f'WARP 连续检查未通过 {count + 1}/3：{failure}')
        if count + 1 >= 3:
            repair(state, folder)
            count_path.unlink(missing_ok=True)
    else:
        count_path.unlink(missing_ok=True)


def probe(address, original=None):
    routes = route_json('route', 'get', '1.1.1.1', 'from', address)
    if not routes or routes[0].get('dev') != DEVICE:
        raise vps.Failure('WARP 源地址未命中独立路由。')
    try:
        direct = tcp_trace()
    except vps.Failure:
        raise vps.Failure('无法检测 VPS 原出口。') from None
    try:
        warp = tcp_trace(address)
    except vps.Failure:
        raise vps.Failure('WARP 的 TCP 出口未通过检测。') from None
    try:
        udp = udp_exit(address)
    except vps.Failure:
        raise vps.Failure('WARP 的 UDP 出口未通过检测。') from None
    if (direct.get('warp') in ('on', 'plus') or warp.get('warp') not in ('on', 'plus')
            or warp['ip'] == direct['ip'] or udp == direct['ip']):
        raise vps.Failure('原系统出口或 WARP TCP / UDP 出口不符合预期。')
    if original and direct['ip'] != original:
        raise vps.Failure('VPS 原系统出口发生变化，停止切换。')
    region = warp.get('loc', '')
    return ExitCheck(direct['ip'], warp['ip'], udp, region if re.fullmatch(r'[A-Z]{2}', region) else '地区未知')


def wait_for_exit(address, original):
    for attempt in range(3):
        try:
            probe(address, original)
            return
        except vps.Failure:
            if attempt == 2:
                raise
            time.sleep(2)


def validate_config(folder, service, cfg):
    path = Path(folder) / (service.core + '.json')
    vps.atomic_json(path, cfg)
    vps.command(vps.config_check(service.core, service.exe, path), timeout=35)


def boot(service, cfg):
    vps.boot(service.unit, service.exe, manage.config_ports(service.core, cfg), vps.sha(service.exe))


def restore(state, folder):
    pending = []
    for core, record in state['cores'].items():
        service = vps.inspect(core, require_running=False)
        cfg = manage.load_config(core)
        if cfg['outbounds'] not in (record['before'], record['after']):
            raise vps.Failure(f'{core} 出站在接管后被修改，保留回退记录。')
        changed = cfg['outbounds'] != record['before']
        cfg['outbounds'] = record['before']
        validate_config(folder, service, cfg)
        recover_service = bool(
            service.pid and changed or state['phase'] == 'applying' and record['active']
            or state['phase'] == 'restoring' and record.get('restart_on_restore')
        )
        record['restart_on_restore'] = recover_service
        pending.append((service, cfg, changed, recover_service))
    state['phase'] = 'restoring'
    vps.atomic_json(state_file(), state)
    for service, cfg, changed, _ in pending:
        if changed:
            vps.atomic_json(service.config, cfg)
    errors = []
    for service, cfg, _, recover_service in pending:
        if recover_service:
            try:
                boot(service, cfg)
            except vps.Failure as error:
                errors.append(str(error))
    if errors:
        raise vps.Failure('直出配置已写回，部分服务重启未确认：' + '；'.join(errors))
    configure_monitor(False)
    stop_link()
    state_file().unlink()
    vps.syncdir(root())


def repair(state, folder):
    if state['phase'] != 'enabled':
        restore(state, folder)
        terminal.result('ok', '上一次回退已完成，当前使用原 VPS 出口。')
        return
    try:
        for attempt in range(3):
            try:
                systemctl('restart', UNIT)
                check = probe(state['address'])
                terminal.result('ok', 'WARP 已重新连通，TCP 和 UDP 检查通过。')
                show_exit(check)
                return
            except vps.Failure:
                if attempt < 2:
                    time.sleep(2)
                else:
                    raise
    except (vps.Failure, KeyboardInterrupt):
        restore(state, folder)
        terminal.result('warning', 'WARP 重连未成功，已回到原 VPS 出口。')
        raise


def enable(folder, accept_terms, imported):
    existing = read_state()
    if existing:
        if existing['phase'] == 'enabled':
            terminal.result('info', 'WARP 已开启。选「1」可检查当前出口。')
            return
        phase = PHASES.get(existing['phase'], '上一次操作未完成')
        raise vps.Failure(f'{phase}。请选「3」恢复原 VPS 出口，再重新开启。')
    manage.check_pending()
    services = []
    configs = {}
    for core in manage.installed():
        service = vps.inspect(core, require_running=False)
        cfg = manage.load_config(core)
        if manage.config_inbounds(core, cfg):
            patch_config(core, cfg, '172.16.0.2')
            configs[core] = cfg
            services.append(service)
    if not services:
        raise vps.Failure('未找到 RayZento 管理的 Xray 或 sing-box 节点。')
    terminal.result('info', '正在检查 VPS 原出口和 WARP 隧道，请稍候。')
    original = tcp_trace()
    if original.get('warp') in ('on', 'plus'):
        raise vps.Failure('系统出口已经经过 WARP，先处理已有的系统级接管。')
    install_wireguard()
    address, mtu, wg_config = profile(imported or registration(accept_terms))
    check_link_free(address)
    if any(os.path.lexists(root() / name) for name in ('active.conf', 'link.sh')):
        raise vps.Failure('发现已有 WireGuard 文件，请先核对上一轮恢复。')
    state = {'phase': 'preparing', 'address': address, 'cores': {}}
    candidates = {}
    for service in services:
        core = service.core
        candidate = patch_config(core, configs[core], address)
        validate_config(folder, service, candidate)
        state['cores'][core] = {'before': configs[core]['outbounds'], 'after': candidate['outbounds'],
                                'active': bool(service.pid)}
        candidates[core] = candidate
    vps.atomic_json(state_file(), state)
    try:
        start_link(address, mtu, wg_config)
        wait_for_exit(address, original['ip'])
        for service in services:
            core_probe(folder, service, candidates[service.core], original['ip'])
        names = '、'.join(service.core for service in services)
        terminal.result('info', f'{names} 的 TCP 和 UDP 出站预检通过，正在切换代理服务。')
        state['phase'] = 'applying'
        vps.atomic_json(state_file(), state)
        for service in services:
            cfg = candidates[service.core]
            vps.atomic_json(service.config, cfg)
            if service.pid:
                boot(service, cfg)
        check = probe(address, original['ip'])
        state['phase'] = 'enabled'
        vps.atomic_json(state_file(), state)
    except BaseException:
        try:
            restore(state, folder)
            terminal.result('warning', '切换未完成，已自动恢复原 VPS 出口。')
        except (vps.Failure, OSError, ValueError, KeyError) as error:
            terminal.result('error', f'自动回退未完成，已保留恢复记录。请选「3」重试恢复。原因：{error}')
        raise
    terminal.result('ok', 'WARP 已开启，受管节点的新 IPv4 连接使用 WARP。')
    show_exit(check)


def show_status(state):
    if not state:
        terminal.result('info', 'RayZento 的 WARP 已关闭。')
        try:
            current = tcp_trace()
        except vps.Failure:
            terminal.result('warning', '本次未能确认 VPS 的公网 IPv4。')
        else:
            print(f'  VPS 当前出口    {current["ip"]}')
            if current.get('warp') in ('on', 'plus'):
                terminal.result('warning', '系统流量仍经 WARP，可能有其他接管配置。')
        return
    phase = state['phase']
    if phase != 'enabled':
        terminal.result('warning', f'{PHASES.get(phase, "操作未完成")}。请选「3」恢复原 VPS 出口。')
        return
    terminal.result('info', '正在检查 WARP 的 TCP 和 UDP 出口，请稍候。')
    for core, record in state['cores'].items():
        if manage.load_config(core)['outbounds'] != record['after']:
            raise vps.Failure(f'WARP 配置为开启，但 {core} 出站配置已变化。请先排查配置。')
    try:
        check = probe(state['address'])
    except vps.Failure as error:
        raise vps.Failure(f'WARP 配置为开启，但实际出口检查失败。{error}') from None
    terminal.result('ok', 'WARP 已开启，TCP 和 UDP 出口检查通过。')
    show_exit(check)
    print(f"  定时恢复        {'已开启' if monitor_running() else '已关闭'}")


def run(action, *, accept_terms=False, imported=None):
    vps.host_check()
    with vps.lock():
        root().mkdir(mode=0o700, exist_ok=True)
        vps.root_owned_path(root())
        if root().is_symlink() or root().stat().st_mode & 0o077:
            raise vps.Failure('WARP 状态目录须为 0700。')
        with tempfile.TemporaryDirectory(prefix='warp-', dir=root()) as folder:
            state = read_state()
            if action == 'on':
                enable(folder, accept_terms, imported)
            elif action == 'status':
                show_status(state)
            elif action == 'sites':
                if state and state['phase'] == 'enabled':
                    try:
                        probe(state['address'])
                    except vps.Failure as error:
                        terminal.result('warning', f'{error} 本次只检测原 VPS 出口。')
                        compare_sites()
                    else:
                        compare_sites(state['address'])
                else:
                    reason = 'WARP 尚未完成切换或回退' if state else 'WARP 已关闭'
                    terminal.result('info', f'{reason}，本次只检测原 VPS 出口。')
                    compare_sites()
            elif action == 'watch-off':
                configure_monitor(False)
                terminal.result('ok', '定时恢复已关闭。')
            elif action == 'monitor':
                monitor(state, folder)
            elif action == 'watch-log':
                print(vps.command(['/usr/bin/journalctl', '-u', MONITOR_UNIT, '-n', '25',
                                   '--no-pager', '-o', 'short-iso']).stdout.decode(errors='replace'))
            elif not state:
                if action == 'watch-on':
                    raise vps.Failure('先开启并验收 WARP，再打开定时恢复。')
                terminal.result('info', 'WARP 已关闭，当前使用原 VPS 出口。')
            elif action == 'watch-on':
                if state['phase'] != 'enabled':
                    raise vps.Failure('WARP 未完成启用，请先恢复上一次操作。')
                configure_monitor(True)
                terminal.result('ok', '定时恢复已开启。连续三轮失败会重连，重连仍失败则恢复原 VPS 出口。')
            elif action == 'off':
                restore(state, folder)
                terminal.result('ok', 'WARP 已关闭，已恢复原 VPS 出口。')
            elif action == 'repair':
                repair(state, folder)
