#!/usr/bin/env bash
set -euo pipefail

fail() {
    printf 'RayZento 安装停止：%s\n' "$*" >&2
    exit 1
}

install_dependencies() {
    local package
    local -a missing=()
    for package in curl ca-certificates python3 iproute2 openssl procps kmod mount util-linux qrencode; do
        if [[ "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)" != installed ]]; then
            missing+=("$package")
        fi
    done
    if (( ${#missing[@]} )); then
        printf '安装缺少的系统依赖：%s\n' "${missing[*]}"
        "$@" apt-get update </dev/null
        "$@" env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${missing[@]}" </dev/null
    fi
    python3 -I -c 'import sys; raise SystemExit(sys.version_info < (3, 10))' ||
        fail '需要 Python 3.10 或更新版本。'
}

main() {
    local repo='__RAYZENTO_REPO__' tag='__RAYZENTO_TAG__' github_cli=0
    local work base digest name extra version os_id os_version machine
    local -a admin=()
    while (( $# )); do
        case "$1" in
            --repo) [[ $# -ge 2 ]] || fail '--repo 缺少参数。'; repo=$2; shift 2 ;;
            --tag) [[ $# -ge 2 ]] || fail '--tag 缺少参数。'; tag=$2; shift 2 ;;
            --github-cli) github_cli=1; shift ;;
            *) fail "不支持的参数 $1。" ;;
        esac
    done
    [[ $repo =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]] ||
        fail '请使用发布页面的 install.sh，或传入 --repo OWNER/RayZento。'
    [[ $tag =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] ||
        fail '请使用发布页面的 install.sh，或传入 --tag vX.Y.Z。'
    [[ "$(uname -s)" == Linux && -r /etc/os-release ]] || fail '需要 Linux VPS。'
    os_id=$(sed -n 's/^ID=//p' /etc/os-release | tr -d '"')
    os_version=$(sed -n 's/^VERSION_ID=//p' /etc/os-release | tr -d '"')
    case "$os_id:$os_version" in
        debian:12|debian:13|ubuntu:22.04|ubuntu:24.04|ubuntu:26.04) ;;
        *) fail "当前为 $os_id ${os_version}。支持 Debian 12/13、Ubuntu 22.04/24.04/26.04 LTS。" ;;
    esac
    machine=$(uname -m)
    case "$machine" in
        x86_64|amd64|aarch64|arm64) ;;
        *) fail "当前架构 $machine 未支持，需 amd64 或 arm64。" ;;
    esac
    [[ -d /run/systemd/system && -r /proc/1/comm && "$(< /proc/1/comm)" == systemd ]] ||
        fail '需要实际运行 systemd，且 PID 1 为 systemd。'
    printf '检测到 %s %s · %s · systemd\n' "$os_id" "$os_version" "$machine"
    if (( EUID != 0 )); then
        command -v sudo >/dev/null || fail '需要 sudo 或 root。'
        admin=(sudo)
    fi
    install_dependencies "${admin[@]}"
    umask 077
    work=$(mktemp -d)
    trap "$(printf 'rm -rf -- %q' "$work")" EXIT
    if (( github_cli )); then
        command -v gh >/dev/null || fail '私有仓库需要已登录的 GitHub CLI。'
        gh release download "$tag" --repo "$repo" --pattern rayzento --pattern rayzento.sha256 --dir "$work"
    else
        command -v curl >/dev/null || fail '需要 curl 下载发布文件。'
        base="https://github.com/$repo/releases/download/$tag"
        curl -q -fsSL --proto '=https' --proto-redir '=https' --retry 2 "$base/rayzento" -o "$work/rayzento"
        curl -q -fsSL --proto '=https' --proto-redir '=https' --retry 2 "$base/rayzento.sha256" -o "$work/rayzento.sha256"
    fi
    read -r digest name extra < "$work/rayzento.sha256" || fail '缺少校验记录。'
    [[ $digest =~ ^[a-f0-9]{64}$ && $name == rayzento && -z $extra ]] ||
        fail 'SHA-256 校验记录格式错误。'
    (cd "$work" && printf '%s  rayzento\n' "$digest" | sha256sum --strict -c -) ||
        fail '发布文件的 SHA-256 校验失败。'
    version=$(python3 -I "$work/rayzento" --version)
    [[ $version == "RayZento ${tag#v}" ]] || fail "下载的版本与标签 $tag 不符。"
    python3 -I "$work/rayzento" doctor
    "${admin[@]}" python3 -I "$work/rayzento" register --yes
    rm -rf -- "$work"
    trap - EXIT
    if [[ -t 1 ]] && ( : </dev/tty ) 2>/dev/null; then
        printf '安装完成，正在打开数字管理菜单。\n'
        exec "${admin[@]}" /usr/local/bin/rayzento menu </dev/tty
    fi
    printf '安装完成。当前没有交互式终端；登录 SSH 终端后运行 rayzento（非 root 用户：sudo rayzento）打开菜单。\n'
}

main "$@"
