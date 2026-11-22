"""Exercise the shipped Ansible package role using local Debian fixtures."""
import argparse
from functools import partial
import hashlib
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading


def run(*argv, env=None, check=True):
    return subprocess.run(argv, env=env, check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)


class Handler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass


def smoke(root, install):
    repo = Path(__file__).resolve().parents[1]
    arch = run("dpkg", "--print-architecture").stdout.strip()
    stage = root / "stage"
    stage.mkdir(mode=0o700)
    web = root / "web"
    release = web / "v99.0.0"
    release.mkdir(parents=True)
    manifest = release / "checksums.txt"
    env = dict(os.environ, ANSIBLE_ROLES_PATH=str(repo / "deploy/ansible/roles"),
               ANSIBLE_LOCAL_TEMP=str(root / "ansible"), ANSIBLE_NOCOLOR="1",
               ANSIBLE_HOST_KEY_CHECKING="True")
    server = ThreadingHTTPServer(("127.0.0.1", 0), partial(Handler, directory=web))
    base = f"http://127.0.0.1:{server.server_port}"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for component in ("nebula-agent", "nebula-mgmt"):
            name = f"{component}-verified-package-smoke"
            fixture = root / name
            control = fixture / "DEBIAN"
            control.mkdir(parents=True)
            marker = Path("/usr/share") / name / "fixture.txt"
            payload = fixture / marker.relative_to("/")
            payload.parent.mkdir(parents=True)
            payload.write_text(name + "\n")
            (control / "control").write_text(f"Package: {name}\nVersion: 99.0.0\nArchitecture: {arch}\nMaintainer: CI <ci@example.org>\nDescription: Isolated Ansible smoke fixture\n")
            asset = release / f"{component}_99.0.0_linux_{arch}.deb"
            run("dpkg-deb", "--root-owner-group", "--build", str(fixture), str(asset))
            digest = hashlib.sha256(asset.read_bytes()).hexdigest()
            good = f"{digest}  {asset.name}\n"
            playbook = root / "smoke.json"
            playbook.write_text(json.dumps([{
                "hosts": "localhost", "connection": "local", "gather_facts": False,
                "become": install, "environment": {"TMPDIR": str(stage)},
                "vars": {"ansible_os_family": "Debian", "ansible_python_interpreter": "/usr/bin/python3",
                         "nebula_package_component": component,
                         "nebula_package_release": "v99.0.0", "nebula_package_arch": arch,
                         "nebula_package_base_url": base},
                "roles": ["nebula_verified_package"],
            }]))
            cases: list[tuple[str, str, str | None]] = [("missing", "", "exactly one SHA-256 line"),
                     ("duplicate", good * 2, "exactly one SHA-256 line"),
                     ("mismatch", f"{'0' * 64}  {asset.name}\n", "checksum")]
            if install:
                cases.append(("valid", good, None))
            for case, manifest_text, error in cases:
                manifest.write_text(manifest_text)
                result = run("ansible-playbook", "-i", "localhost,", str(playbook), env=env, check=False)
                if error:
                    assert result.returncode == 2 and error.lower() in result.stdout.lower(), result.stdout
                    if case == "mismatch":
                        assert "did not match" in result.stdout and "Install verified Debian package" not in result.stdout, result.stdout
                    assert not marker.exists(), f"{component}/{case} unexpectedly installed a fixture"
                else:
                    assert result.returncode == 0, result.stdout
                    assert marker.read_bytes() == payload.read_bytes()
                    run("sudo", "-n", "dpkg", "--purge", name)
                    assert not marker.exists()
                assert not list(stage.glob("nebula-package-*")), result.stdout
                print(f"{component}/{case}: verified", flush=True)
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--ci-install", action="store_true")
    args = parser.parse_args()
    if args.ci_install and os.environ.get("GITHUB_ACTIONS") != "true":
        parser.error("--ci-install is only for an isolated hosted GitHub Actions runner")
    with tempfile.TemporaryDirectory(prefix="nebula-ansible-smoke-") as temp:
        smoke(Path(temp), args.ci_install)
