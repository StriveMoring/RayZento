"""Public website and temporary core egress checks for the WARP menu."""

import copy
from dataclasses import dataclass
import ipaddress
import os
from pathlib import Path
import re
import secrets
import socket
import struct
import subprocess
import time
from urllib.parse import urlsplit

import rayzento_core as vps
import rayzento_terminal as terminal


TRACE = 'https://www.cloudflare.com/cdn-cgi/trace'
COOKIE = 0x2112A442
SITES = (
    ('Google 搜索', 'https://www.google.com/search?q=weather'),
    ('Gemini', 'https://gemini.google.com/app'),
    ('Google AI Studio', 'https://aistudio.google.com/'),
    ('Netflix 全球剧样本', 'https://www.netflix.com/title/80057281'),
    ('Netflix 片库样本', 'https://www.netflix.com/title/70143836'),
    ('ChatGPT', 'https://chatgpt.com/'),
)


def curl_args():
    return ['/usr/bin/curl', '-q', '-4sS', '--noproxy', '*', '--proto', '=https', '--max-time', '9']


def parse_trace(body):
    fields = dict(line.split('=', 1) for line in body.splitlines() if '=' in line)
    try:
        address = ipaddress.IPv4Address(fields['ip'])
        if not address.is_global:
            raise ValueError
    except (ValueError, KeyError):
        raise vps.Failure('未能读取公网 IPv4 出口。') from None
    return fields


def trace(source=None):
    command = curl_args() + ['--fail']
    if source:
        command += ['--interface', source]
    return parse_trace(vps.command(command + [TRACE]).stdout.decode())


def stun_target():
    return socket.getaddrinfo('stun.cloudflare.com', 3478, socket.AF_INET, socket.SOCK_DGRAM)[0][4]


def stun_request():
    token = os.urandom(12)
    return struct.pack('!HHI12s', 1, 0, COOKIE, token), token


def stun_address(packet, token):
    if len(packet) >= 20:
        kind, size, magic, tid = struct.unpack_from('!HHI12s', packet)
        if kind == 0x101 and magic == COOKIE and tid == token and size + 20 <= len(packet):
            offset = 20
            while offset + 4 <= size + 20:
                attr, length = struct.unpack_from('!HH', packet, offset)
                start = offset + 4
                if attr == 0x20 and length == 8 and start + length <= size + 20 and packet[start + 1] == 1:
                    address = ipaddress.IPv4Address(struct.unpack_from('!I', packet, start + 4)[0] ^ COOKIE)
                    if address.is_global:
                        return str(address)
                offset = start + (length + 3) // 4 * 4
    raise vps.Failure('STUN 回复没有有效的公网 IPv4。')


def udp_exit(source):
    request, token = stun_request()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            udp.bind((source or '0.0.0.0', 0))
            udp.connect(stun_target())
            udp.send(request)
            return stun_address(udp.recv(2048), token)
    except OSError:
        raise vps.Failure('WARP UDP STUN 测试连接失败。') from None


def read_exact(sock, size):
    result = bytearray()
    while len(result) < size:
        part = sock.recv(size - len(result))
        if not part:
            raise vps.Failure('SOCKS5 验收连接提前关闭。')
        result.extend(part)
    return bytes(result)


def socks_udp_exit(port, password):
    # Use the SOCKS5 UDP ASSOCIATE from the real core, rather than a direct UDP probe.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp, socket.create_connection(('127.0.0.1', port), timeout=4) as control:
            udp.settimeout(5)
            udp.bind(('127.0.0.1', 0))
            control.sendall(b'\x05\x01\x02')
            if read_exact(control, 2) != b'\x05\x02':
                raise vps.Failure('临时核心未要求 SOCKS5 代理认证。')
            control.sendall(b'\x01\x05probe' + bytes([len(password)]) + password.encode('ascii'))
            if read_exact(control, 2) != b'\x01\x00':
                raise vps.Failure('临时核心拒绝 SOCKS5 验证。')
            control.sendall(b'\x05\x03\x00\x01' + socket.inet_aton('127.0.0.1') + struct.pack('!H', udp.getsockname()[1]))
            if read_exact(control, 4) != b'\x05\x00\x00\x01':
                raise vps.Failure('临时核心未提供 IPv4 UDP 代理。')
            relay = socket.inet_ntoa(read_exact(control, 4))
            relay_port = struct.unpack('!H', read_exact(control, 2))[0]
            if relay not in ('0.0.0.0', '127.0.0.1') or relay_port == 0:
                raise vps.Failure('临时核心返回了非回环 UDP 地址。')
            endpoint, target_port = stun_target()
            request, token = stun_request()
            udp.connect(('127.0.0.1', relay_port))
            udp.send(b'\x00\x00\x00\x01' + socket.inet_aton(endpoint) + struct.pack('!H', target_port) + request)
            reply = udp.recv(2048)
            if reply[:4] != b'\x00\x00\x00\x01' or len(reply) < 10:
                raise vps.Failure('临时核心的 UDP 回包格式异常。')
            return stun_address(reply[10:], token)
    except OSError:
        raise vps.Failure('经临时核心发送 UDP STUN 失败。') from None


def core_probe(folder, service, candidate, native_ip):
    """Run the exact candidate outbound with a short-lived authenticated listener."""
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    password = secrets.token_hex(24)
    if service.core == 'xray':
        inbound = {'protocol': 'socks', 'listen': '127.0.0.1', 'port': port,
                   'settings': {'auth': 'password', 'accounts': [{'user': 'probe', 'pass': password}],
                                'udp': True, 'ip': '127.0.0.1'}}
    else:
        inbound = {'type': 'socks', 'listen': '127.0.0.1', 'listen_port': port,
                   'users': [{'username': 'probe', 'password': password}]}
    config = copy.deepcopy(candidate)
    config['inbounds'] = [inbound]
    path = Path(folder) / (service.core + '-probe.json')
    vps.atomic_json(path, config)
    with subprocess.Popen(list(map(str, vps.core_command(service.core, service.exe, path))),
                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as proc:
        try:
            for _ in range(12):
                if proc.poll() is not None:
                    raise vps.Failure(f'{service.core} 隔离测试进程未能启动。')
                if f'tcp 127.0.0.1:{port}' in vps.listeners(proc.pid):
                    break
                time.sleep(.25)
            else:
                raise vps.Failure(f'{service.core} 隔离测试进程未开启监听。')
            opts = f'proxy = "socks5h://127.0.0.1:{port}"\nproxy-user = "probe:{password}"\n'
            args = curl_args()
            args[args.index('*')] = ''
            result = vps.command(args + ['--fail', '-K', '-', TRACE], input=opts.encode()).stdout.decode()
            tcp = parse_trace(result)
            udp = socks_udp_exit(port, password)
            if tcp.get('warp') not in ('on', 'plus') or native_ip in (tcp['ip'], udp):
                raise vps.Failure(f'{service.core} 测到原 VPS 出口或未确认 WARP。')
        finally:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=4)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()


@dataclass(frozen=True)
class PageResult:
    kind: str
    text: str


def page_result(body, code, host):
    # Only label observations from the public response, regardless of the HTTP code.
    snippets = (
        (r'not (?:currently )?available in your (?:country|region)|unsupported_country', '检测到地区限制'),
        (r'you seem to be using (?:a |an )?(?:vpn|proxy)', '检测到代理限制'),
        (r'<title>\s*(?:just a moment|attention required)', '遇到验证页'),
    )
    for pattern, label in snippets:
        if re.search(pattern, body, re.I):
            return PageResult('warning', label)
    if re.fullmatch(r'(?:www\.)?google\.com\.hk', host):
        return PageResult('warning', '跳转香港站')
    if code in ('401', '403', '429'):
        message = '触发限流' if code == '429' else '访问受限'
        return PageResult('warning', f'{message} · HTTP {code}')
    if re.fullmatch(r'2[0-9]{2}', code):
        return PageResult('ok', '页面可达')
    if re.fullmatch(r'3[0-9]{2}', code):
        return PageResult('warning', f'仍有跳转 · HTTP {code}')
    if re.fullmatch(r'[45][0-9]{2}', code):
        return PageResult('error', f'请求失败 · HTTP {code}')
    return PageResult('error', '未收到有效响应')


def public_site(url, source):
    args = curl_args() + ['-A', 'Mozilla/5.0 RayZento/egress-check', '-L', '--max-redirs', '4',
                          '--max-filesize', '2097152', '-w', '\n%{http_code} %{url_effective}']
    if source:
        args += ['--interface', source]
    try:
        result = vps.command(args + [url]).stdout.decode(errors='replace')
    except vps.Failure:
        return PageResult('error', '连接未完成')
    body, _, metadata = result.rpartition('\n')
    code, _, destination = metadata.partition(' ')
    return page_result(body, code, urlsplit(destination).hostname or '')


def compare_sites(source=None):
    print(f"\n{terminal.color('网站检测 · 逐项检查公开页面', 'heading')}", flush=True)
    paths = [('原 VPS 出口', None)]
    if source:
        paths.append(('WARP 出口', source))
    results = {name: [] for name, _ in paths}
    for label, url in SITES:
        statuses = []
        for name, address in paths:
            check = public_site(url, address)
            results[name].append(check.kind)
            statuses.append(f'{name} {terminal.badge(check.kind, check.text)}')
        print(f"  {label}  {'  /  '.join(statuses)}", flush=True)
    print('\n  检测汇总')
    for name, checks in results.items():
        print(f"    {name}  {checks.count('ok')} 项页面可达 · {checks.count('warning')} 项需留意 · {checks.count('error')} 项未通过")
    print('  页面可达只代表公开网页有响应。登录、Netflix 片库及播放需在客户端实测。')
