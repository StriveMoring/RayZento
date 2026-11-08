```bash
bash -c 'set -euo pipefail
if [ "$(id -u)" -eq 0 ]; then
    apt-get update
    apt-get install -y --no-install-recommends curl ca-certificates
else
    command -v sudo >/dev/null || { echo "请使用 root 运行此命令。" >&2; exit 1; }
    sudo apt-get update
    sudo apt-get install -y --no-install-recommends curl ca-certificates
fi
curl -q -fsSL --proto "=https" --proto-redir "=https" --retry 2 https://github.com/StriveMoring/RayZento/releases/latest/download/install.sh | bash'
```
