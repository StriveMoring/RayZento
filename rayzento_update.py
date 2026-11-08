"""RayZento release updates use the same repository that built the executable."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import zipfile

import homegateway_vps as vps

REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*")
COMMAND_PATH = Path("/usr/local/bin/rayzento")


def build_info():
    source = Path(sys.argv[0]).resolve(strict=True)
    try:
        with zipfile.ZipFile(source) as archive:
            data = json.loads(archive.read("rayzento-release.json"))
    except (KeyError, zipfile.BadZipFile):
        raise vps.Failure("请使用 GitHub Release 构建的 RayZento。") from None
    if not REPOSITORY.fullmatch(data.get("repository") or ""):
        raise vps.Failure("当前文件没有绑定发布仓库。上传 GitHub 并通过 Release 工作流生成发布文件。")
    return data


def preview():
    info = build_info()
    repo = info["repository"]
    obj = json.loads(vps.fetch(f"https://api.github.com/repos/{repo}/releases/latest", 4 * 1024 * 1024))
    tag = vps.version(obj.get("tag_name", ""))
    if obj.get("draft") or obj.get("prerelease"):
        raise vps.Failure("没有可用的正式版。")
    asset = next((a for a in obj.get("assets", []) if a["name"] == "rayzento"), None)
    expected = f"https://github.com/{repo}/releases/download/{tag}/rayzento"
    if not asset or asset.get("browser_download_url") != expected:
        raise vps.Failure("发布附件缺失或不在绑定仓库。")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", asset.get("digest") or ""):
        raise vps.Failure("GitHub 未提供发布附件的 SHA-256。")
    if not isinstance(asset.get("size"), int) or not 0 < asset["size"] <= 8 * 1024 * 1024:
        raise vps.Failure("管理器发布文件大小异常。")
    print(f"RayZento {vps.VERSION} → {tag} · {repo}")
    return info, tag, asset


def replace_tool(source):
    target = COMMAND_PATH
    if target.is_symlink() or not target.is_file():
        raise vps.Failure("需要先注册 rayzento 管理命令。")
    vps.root_owned_path(target)
    with tempfile.NamedTemporaryFile(prefix=".rayzento-update-", dir=target.parent, delete=False) as temp:
        staged = Path(temp.name)
        try:
            shutil.copyfile(source, staged)
            staged.chmod(0o755)
            result = vps.command([sys.executable, "-I", staged, "--version"])
            if not result.stdout.decode().strip().startswith("RayZento "):
                raise vps.Failure("候选管理器版本验证失败。")
            with staged.open("rb") as f:
                os.fsync(f.fileno())
            os.replace(staged, target)
            vps.syncdir(target.parent)
        finally:
            staged.unlink(missing_ok=True)


def update(candidate):
    info, tag, asset = candidate
    if vps.tag_numbers(tag) <= vps.tag_numbers("v" + vps.VERSION):
        print("当前管理器已经是此仓库的相同或更新版本。")
        return False
    blob = vps.fetch(asset["browser_download_url"], asset["size"], max_seconds=120)
    if len(blob) != asset["size"] or "sha256:" + hashlib.sha256(blob).hexdigest() != asset["digest"]:
        raise vps.Failure("管理器下载校验失败。")
    with vps.lock():
        target = COMMAND_PATH
        if target.resolve() != Path(sys.argv[0]).resolve():
            raise vps.Failure("请从已注册的 sudo rayzento 运行脚本更新。")
        current = vps.command([sys.executable, "-I", target, "--version"]).stdout.decode().strip()
        if not current.startswith("RayZento "):
            raise vps.Failure("无法确认当前管理器版本。")
        installed_tag = vps.version(current.removeprefix("RayZento "))
        if vps.tag_numbers(installed_tag) >= vps.tag_numbers(tag):
            print("另一项更新已完成，当前管理器已达到此版本。")
            return False
        folder = vps.ROOT / "tool-backup"
        if folder.is_symlink():
            raise vps.Failure("脚本备份路径是符号链接。")
        folder.mkdir(mode=0o700, exist_ok=True)
        vps.root_owned_path(folder)
        saved = folder / "rayzento.before"
        with tempfile.NamedTemporaryFile(prefix=".new-tool-", dir=folder, delete=False) as f:
            candidate_file = Path(f.name)
            try:
                f.write(blob)
                f.flush()
                os.fsync(f.fileno())
                with zipfile.ZipFile(candidate_file) as archive:
                    metadata = json.loads(archive.read("rayzento-release.json"))
                if metadata.get("repository") != info["repository"] or metadata.get("tag") != tag:
                    raise vps.Failure("候选管理器的仓库或版本不符。")
                result = vps.command([sys.executable, "-I", candidate_file, "--version"])
                if result.stdout.decode().strip() != f"RayZento {tag[1:]}":
                    raise vps.Failure("候选管理器无法运行。")
                shutil.copy2(target, saved)
                saved.chmod(0o700)
                vps.atomic_json(folder / "record.json", {"before_sha": vps.sha(saved),
                                                       "after_sha": vps.sha(candidate_file)})
                replace_tool(candidate_file)
            finally:
                candidate_file.unlink(missing_ok=True)
    print("RayZento 已更新。当前菜单退出，重新运行 sudo rayzento 使用新版。")
    return True


def rollback():
    with vps.lock():
        folder = vps.ROOT / "tool-backup"
        vps.root_owned_path(folder)
        saved = folder / "rayzento.before"
        record = json.loads((folder / "record.json").read_text())
        target = COMMAND_PATH
        if saved.is_symlink() or vps.sha(saved) != record["before_sha"] or vps.sha(target) != record["after_sha"]:
            raise vps.Failure("脚本备份或当前文件已变化。")
        replace_tool(saved)
    print("已恢复上一版管理器。重新运行 sudo rayzento。")
