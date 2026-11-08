"""Build the RayZento executable, SHA-256 manifest and Bash installer."""
import argparse
import hashlib
from pathlib import Path
import re
import json
import zipfile

from homegateway_vps import VERSION


SOURCE = Path(__file__).resolve().parent
MODULES = (
    "__main__.py",
    "homegateway_provision.py",
    "homegateway_vps.py",
    "rayzento_compat.py",
    "rayzento_menu.py",
    "rayzento_tune.py",
    "rayzento_nodes.py",
    "rayzento_manage.py",
    "rayzento_certificates.py",
    "rayzento_update.py",
)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", default=f"v{VERSION}")
    parser.add_argument("--repo", help="GitHub OWNER/REPO to bind into install.sh")
    parser.add_argument("--output", type=Path, default=Path("dist"))
    args = parser.parse_args()
    if args.tag != f"v{VERSION}":
        parser.error(f"版本标签须为 v{VERSION}，收到 {args.tag!r}。")
    if args.repo is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*", args.repo):
        parser.error("--repo 需要 GitHub OWNER/REPO。")

    args.output.mkdir(parents=True, exist_ok=True)
    executable = args.output / "rayzento"
    with executable.open("wb") as stream:
        stream.write(b"#!/usr/bin/env python3\n")
        with zipfile.ZipFile(stream, "w") as archive:
            for name in MODULES:
                entry = zipfile.ZipInfo(name)
                entry.create_system = 3
                entry.external_attr = 0o100644 << 16
                archive.writestr(entry, (SOURCE / name).read_bytes())
            entry = zipfile.ZipInfo("rayzento-release.json")
            entry.create_system = 3
            entry.external_attr = 0o100644 << 16
            archive.writestr(entry, json.dumps({"repository": args.repo, "tag": args.tag}))
    executable.chmod(0o755)
    digest = hashlib.sha256(executable.read_bytes()).hexdigest()
    (args.output / "rayzento.sha256").write_text(f"{digest}  rayzento\n", encoding="ascii")
    installer = (SOURCE / "install.sh").read_text(encoding="utf-8").replace("__RAYZENTO_TAG__", args.tag)
    if args.repo:
        installer = installer.replace("__RAYZENTO_REPO__", args.repo)
    path = args.output / "install.sh"
    path.write_text(installer, encoding="utf-8")
    path.chmod(0o755)
    print(f"{args.tag}: {executable}")


if __name__ == "__main__":
    main()
