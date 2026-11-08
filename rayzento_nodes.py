"""Node inventory, copyable links and client exports."""
import base64
import contextlib
import ipaddress
import json
from urllib.parse import quote, urlencode, urlsplit

import rayzento_core as vps


def ordered(nodes):
    from rayzento_provision import PROFILE_ORDER
    rank = {name: index for index, name in enumerate(PROFILE_ORDER)}
    return sorted(nodes, key=lambda node: rank.get(node["profile"], len(rank)))


def records(ports, clients, vless_links):
    links = {urlsplit(link).username: link for link in vless_links}
    if len(ports) != len(clients):
        raise vps.Failure("节点元数据数量不一致。")
    return ordered([{"profile": profile, "client": client, "link": links.get(client.get("uuid"), "")}
                    for profile, client in zip(ports, clients)])


def load(core):
    path = vps.OPT / core / "nodes.json"
    if path.is_symlink():
        raise vps.Failure("节点元数据路径是符号链接。")
    vps.root_owned_path(path)
    data = json.loads(path.read_text())
    if not isinstance(data, list) or any(not isinstance(n, dict) for n in data):
        raise vps.Failure("节点元数据无效。")
    return data


def all_nodes():
    import rayzento_provision as provision
    nodes = []
    for core in vps.ORDER:
        if not (vps.OPT / core).exists():
            continue
        vps.inspect(core, require_running=False)
        for node in load(core):
            if node["profile"] not in provision.NAMES or provision.NAMES[node["profile"]][0] != core:
                raise vps.Failure("节点不属于对应的受管核心。")
            nodes.append(node)
    return ordered(nodes)


def public_host(server):
    try:
        ip = ipaddress.ip_address(server)
        if not ip.is_global or ip.version != 4:
            raise vps.Failure("默认节点需要公网 IPv4 或你指定的公网域名。")
    except ValueError:
        import rayzento_certificates as certificates
        certificates.domain(server)
    return server


def detect_address():
    # Require independent responses to agree, so a single failed lookup cannot select an endpoint.
    replies = []
    for url in ("https://www.cloudflare.com/cdn-cgi/trace", "https://api.ipify.org"):
        result = vps.command(["curl", "-q", "-4", "-fsS", "--connect-timeout", "4", "--max-time", "8", url],
                             check=False, timeout=10)
        if result.returncode:
            continue
        body = result.stdout.decode(errors="replace").strip()
        candidate = next((line[3:] for line in body.splitlines() if line.startswith("ip=")), body)
        try:
            value = ipaddress.IPv4Address(candidate)
        except ValueError:
            continue
        if value.is_global:
            replies.append(str(value))
    if len(replies) == 2 and len(set(replies)) == 1:
        print(f"自动识别公网 IPv4 {replies[0]}。NAT 或端口映射 VPS 可在节点管理中修改客户端入口。")
        return replies[0]
    raise vps.Failure("无法可靠确定公网 IPv4。请填写 VPS 的公网入口地址。")


def link(node):
    c = node["client"]
    host = c["server"]
    endpoint = f"{host}:{c['port']}"
    title = quote(c["name"], safe="")
    if c["type"] == "vless":
        if not node.get("link"):
            raise vps.Failure("缺少 VLESS 导出链接。")
        parsed = urlsplit(node["link"])
        return parsed._replace(netloc=f"{quote(c['uuid'], safe='')}@{endpoint}", fragment=title).geturl()
    auth = quote(c["password"], safe="")
    if c["type"] == "tuic":
        query = {"sni": c["sni"], "alpn": "h3", "congestion_control": c["congestion-controller"]}
        return f"tuic://{quote(c['uuid'], safe='')}:{auth}@{endpoint}?{urlencode(query)}#{title}"
    if c["type"] == "anytls":
        query = {"sni": c["sni"]}
        if c.get("reality-opts"):
            options = c["reality-opts"]
            query.update(security="reality", pbk=options["public-key"], sid=options["short-id"], fp="chrome")
        return f"anytls://{auth}@{endpoint}?{urlencode(query)}#{title}"
    if c["type"] == "naive":
        query = urlencode({"sni": c["sni"]})
        return f"naive+https://{quote(c['username'], safe='')}:{auth}@{endpoint}?{query}#{title}"
    raise vps.Failure("未知客户端协议。")


def text_file(path, content):
    path.write_text(content)
    path.chmod(0o600)


def export(nodes=None, *, locked=False):
    nodes = ordered(all_nodes() if nodes is None else nodes)
    with contextlib.nullcontext() if locked else vps.lock():
        folder = vps.ROOT / "exports"
        folder.mkdir(mode=0o700, exist_ok=True)
        if folder.is_symlink():
            raise vps.Failure("拒绝符号链接导出目录。")
        vps.root_owned_path(folder)
        links = [link(n) for n in nodes]
        for name, content in {
            "all-links.txt": "\n".join(links) + "\n",
            "v2rayn-vless.txt": "\n".join(link(n) for n in nodes if n["client"]["type"] == "vless") + "\n",
            "subscription-base64.txt": base64.b64encode(("\n".join(links) + "\n").encode()).decode() + "\n",
        }.items():
            text_file(folder / name, content)
        proxies = [n["client"] for n in nodes if n["client"]["type"] != "naive"]
        vps.atomic_json(folder / "mihomo-proxies.yaml", {"proxies": proxies})
        vps.atomic_json(folder / "all-nodes.json", nodes)
        # JSON is valid YAML, and can be imported as a complete isolated Mihomo profile.
        names = [p["name"] for p in proxies]
        profile = {"mixed-port": 7890, "allow-lan": False, "ipv6": False, "mode": "rule",
                   "proxies": proxies,
                   "proxy-groups": [{"name": "RayZento", "type": "select", "proxies": names or ["DIRECT"]}],
                   "rules": ["MATCH,RayZento"]}
        vps.atomic_json(folder / "mihomo-profile.yaml", profile)
        print(f"导出目录 {folder}，包含节点凭据，仅 root 可读。")
        return folder


def display(nodes=None):
    nodes = ordered(all_nodes() if nodes is None else nodes)
    for node in nodes:
        c = node["client"]
        print(f"\n{node['profile']} · {c['name']} · {c['server']}:{c['port']}")
        uri = link(node)
        print(uri)
        if node["profile"] in ("anytls-reality", "naive"):
            print("该协议的分享 URI 各客户端实现不同，优先参照导出 JSON 的完整参数。")
    if not nodes:
        print("当前没有已安装节点。")
