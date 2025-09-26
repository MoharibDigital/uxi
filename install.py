#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Safer IPTV / Xtream UI installer (Python 3)
- Adds explicit user confirmation, backups, download retries, MySQL auth checks,
  safe extraction into tempdir, and non-invasive systemd creation only if start script exists.
- Designed for company use / testing. Run as root.

Usage:
  sudo python3 iptv_installer_safe.py
"""

import os
import sys
import subprocess
import shutil
import socket
import random
import string
import zipfile
import tarfile
import tempfile
import time
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
from pathlib import Path
from getpass import getpass
from datetime import datetime

# -------------------- CONFIG --------------------
BASE_DIR = Path("/srv/iptv")
INSTALL_DIR = BASE_DIR / "iptv_xtream_codes"
USER = "iptv"
LOG_FILE = Path("/var/log/iptv_install_safe.log")
PACKAGES = [
    "wget", "unzip", "zip", "htop", "mc",
    "libxslt1-dev", "libgeoip-dev", "e2fsprogs",
    "libjemalloc1", "mysql-server", "nginx", "python3-paramiko"
]
DOWNLOAD_RETRIES = 3
MAX_DOWNLOAD_BYTES = 500 * 1024 * 1024  # 500 MB default limit (adjust if needed)
# ------------------------------------------------

def log(msg):
    ts = datetime.utcnow().isoformat() + "Z"
    line = f"[{ts}] {msg}"
    print(line)
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass

def run(cmd, check=True, capture_output=False):
    log(f"RUN: {cmd}")
    if capture_output:
        res = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        log(f"OUT: {res.stdout.strip()}")
        if res.returncode != 0 and res.stderr:
            log(f"ERR: {res.stderr.strip()}")
        if check and res.returncode != 0:
            raise subprocess.CalledProcessError(res.returncode, cmd)
        return res
    else:
        res = subprocess.run(cmd, shell=True)
        if check and res.returncode != 0:
            raise subprocess.CalledProcessError(res.returncode, cmd)
        return res

def ensure_root():
    if os.geteuid() != 0:
        print("This script must be run as root. Use: sudo python3 %s" % sys.argv[0])
        sys.exit(1)

def confirm_user_intent():
    print("\nIMPORTANT: You must have the legal right to install and run the target software.")
    print("This installer will make system changes (packages, users, MySQL, services).")
    ans = input("Do you confirm you have permission and want to proceed? (type 'YES' to continue): ").strip()
    if ans != "YES":
        log("User did not confirm consent. Aborting.")
        sys.exit(1)

def check_disk(min_gb=2):
    try:
        stat = shutil.disk_usage(str(BASE_DIR.parent))
        free_gb = stat.free / (1024 ** 3)
        log(f"Disk free: {free_gb:.2f} GB")
        if free_gb < min_gb:
            raise SystemExit(f"Not enough disk space under {BASE_DIR.parent} (need >= {min_gb} GB).")
    except Exception as e:
        log(f"Disk check failed: {e}")

def apt_update_and_install(pkgs):
    log("Updating apt and installing packages (non-interactive). This may take a while.")
    run("export DEBIAN_FRONTEND=noninteractive && apt-get update -y >> %s 2>&1" % LOG_FILE)
    install_cmd = "apt-get install -y " + " ".join(pkgs) + f" >> {LOG_FILE} 2>&1"
    run(install_cmd)

def create_system_user(user):
    try:
        subprocess.run(["id", user], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        log(f"User {user} already exists")
    except subprocess.CalledProcessError:
        log(f"Creating system user {user}")
        run(f"adduser --system --shell /bin/false --group --disabled-login {user} >> {LOG_FILE} 2>&1")

def secure_directory(path: Path, user: str, mode=0o750):
    path.mkdir(parents=True, exist_ok=True)
    run(f"chown -R {user}:{user} {str(path)}")
    try:
        path.chmod(mode)
    except Exception as e:
        log(f"chmod failed for {path}: {e}")

def url_head_ok(url, timeout=10):
    try:
        req = Request(url, method="HEAD", headers={"User-Agent": "Mozilla/5.0"})
        with urlopen(req, timeout=timeout) as resp:
            return resp.status in (200, 302, 301)
    except Exception:
        return False

def download_file_with_retries(url, dest: Path, max_bytes=MAX_DOWNLOAD_BYTES, retries=DOWNLOAD_RETRIES):
    log(f"Downloading {url} -> {dest} (max {max_bytes} bytes)")
    last_err = None
    for attempt in range(1, retries+1):
        try:
            req = Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urlopen(req, timeout=30) as resp:
                # basic size check if content-length provided
                cl = resp.getheader("Content-Length")
                if cl and int(cl) > max_bytes:
                    raise ValueError(f"Content-Length {cl} exceeds limit {max_bytes}")
                with open(dest, "wb") as out:
                    total = 0
                    while True:
                        chunk = resp.read(65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > max_bytes:
                            raise ValueError("Download exceeded maximum allowed size")
                        out.write(chunk)
            log(f"Downloaded ok ({total} bytes)")
            return
        except Exception as e:
            last_err = e
            log(f"Download attempt {attempt} failed: {e}")
            time.sleep(2 * attempt)
    raise last_err

def extract_archive_safe(archive: Path, dest: Path):
    log(f"Extracting archive {archive} into temp dir and moving content to {dest}")
    if not archive.exists():
        raise FileNotFoundError("Archive not found: %s" % archive)
    with tempfile.TemporaryDirectory() as td:
        tmpd = Path(td)
        if str(archive).endswith((".tar.gz", ".tgz", ".tar")):
            with tarfile.open(archive, "r:*") as tf:
                tf.extractall(path=tmpd)
        elif str(archive).endswith(".zip"):
            with zipfile.ZipFile(archive, "r") as zf:
                zf.extractall(path=tmpd)
        else:
            raise ValueError("Unsupported archive format")
        # identify top-level extracted folder(s)
        entries = list(tmpd.iterdir())
        if not entries:
            raise ValueError("Archive empty or extraction failed")
        # if single top-level directory, move its contents; otherwise move all
        if len(entries) == 1 and entries[0].is_dir():
            src = entries[0]
        else:
            src = tmpd
        # create dest parent and backup existing install dir
        if dest.exists():
            backup = dest.with_name(dest.name + ".backup." + datetime.utcnow().strftime("%Y%m%d%H%M%S"))
            log(f"Backing up existing install at {dest} -> {backup}")
            shutil.move(str(dest), str(backup))
        dest.parent.mkdir(parents=True, exist_ok=True)
        log(f"Moving files from {src} -> {dest}")
        shutil.move(str(src), str(dest))

def try_mysql_command(cmd, root_password=None):
    # cmd: SQL string
    base = "mysql -e \"{}\"".format(cmd.replace('"','\\"'))
    if root_password:
        base = f"mysql -uroot -p'{root_password}' -e \"{cmd.replace('\"','\\\"')}\""
    try:
        run(base, check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        return False

def configure_mysql_safe(db_name, db_user, db_password):
    log("Configuring MySQL database and user (safe mode)")
    sql = (
        f"CREATE DATABASE IF NOT EXISTS `{db_name}` DEFAULT CHARACTER SET utf8mb4;"
        f"CREATE USER IF NOT EXISTS '{db_user}'@'%' IDENTIFIED BY '{db_password}';"
        f"GRANT ALL PRIVILEGES ON `{db_name}`.* TO '{db_user}'@'%';FLUSH PRIVILEGES;"
    )
    # Try without password (socket auth)
    if try_mysql_command("SELECT 1;"):
        run(f"mysql -e \"{sql}\"")
        return True
    # Ask for root password as fallback
    log("Root MySQL socket auth failed. If MySQL uses password auth, provide root password.")
    root_pw = getpass("MySQL root password (leave blank to abort): ")
    if not root_pw:
        raise SystemExit("MySQL configuration aborted by user.")
    if try_mysql_command("SELECT 1;", root_password=root_pw):
        run(f"mysql -uroot -p'{root_pw}' -e \"{sql}\"")
        return True
    raise RuntimeError("MySQL commands failed even after providing root password.")

def generate_password(length=24):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def create_systemd_service_if_needed(user, install_dir):
    start_sh = install_dir / "start_services.sh"
    svc_file = Path("/etc/systemd/system/iptv-services.service")
    if start_sh.exists():
        log("Found start_services.sh, creating systemd service wrapper.")
        svc_text = f"""[Unit]
Description=IPTV services wrapper
After=network.target mysql.service

[Service]
Type=simple
User={user}
Group={user}
WorkingDirectory={install_dir}
ExecStart=/bin/bash -lc 'exec {install_dir}/start_services.sh'
Restart=on-failure

[Install]
WantedBy=multi-user.target
"""
        svc_file.write_text(svc_text)
        run("systemctl daemon-reload && systemctl enable iptv-services.service")
        try:
            run("systemctl start iptv-services.service")
        except Exception as e:
            log(f"Starting iptv-services.service failed: {e}")
    else:
        log("No start_services.sh found — skipping systemd service creation (non-invasive).")

def write_config_file_safe(install_dir, user, db_name, db_user, db_password):
    cfg_dir = install_dir
    cfg_path = cfg_dir / "config"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    cfg_content = f'{{"host":"127.0.0.1","db_user":"{db_user}","db_pass":"{db_password}","db_name":"{db_name}","server_id":"1","db_port":"3306"}}'
    try:
        tmp = cfg_path.with_suffix(".tmp")
        tmp.write_text(cfg_content)
        run(f"chown {user}:{user} {str(tmp)}")
        tmp.chmod(0o600)
        tmp.replace(cfg_path)
        log(f"Wrote config to {cfg_path} (mode 600)")
    except Exception as e:
        log(f"Failed to write config file: {e}")

def get_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

def main():
    ensure_root()
    confirm_user_intent()
    log("Starting safer IPTV installer")

    # ask for tarball url (company mirror recommended)
    tarball_url = input("Enter full URL to application tar.gz or zip (company mirror recommended):\n> ").strip()
    if not tarball_url:
        log("No URL provided - aborting.")
        sys.exit(1)
    if not url_head_ok(tarball_url):
        log("Warning: HEAD check failed for URL. Continue only if you trust the source.")
        if input("Continue despite failed HEAD? (yes/no): ").strip().lower() != "yes":
            sys.exit(1)

    # basic system checks
    check_disk(min_gb=2)

    # optionally install packages (ask user)
    if input("Install required packages via apt? (recommended) [yes/no]: ").strip().lower() == "yes":
        apt_update_and_install(PACKAGES)
    else:
        log("Skipping package installation (user chose no).")

    # create service user and directories
    create_system_user(USER)
    secure_directory(BASE_DIR, USER)
    
    # Download to a temporary file
    tmp_archive = Path(tempfile.gettempdir()) / f"iptv_pkg_{int(time.time())}"
    try:
        download_file_with_retries(tarball_url, tmp_archive)
    except Exception as e:
        log(f"Download failed: {e}")
        sys.exit(1)

    # Extract safely and move into place (backup existing)
    try:
        extract_archive_safe(tmp_archive, INSTALL_DIR)
    except Exception as e:
        log(f"Extraction/install move failed: {e}")
        # try to cleanup
        try:
            tmp_archive.unlink()
        except Exception:
            pass
        sys.exit(1)
    finally:
        try:
            tmp_archive.unlink()
        except Exception:
            pass

    # fix ownership and permissions
    run(f"chown -R {USER}:{USER} {str(INSTALL_DIR)}")
    for c in INSTALL_DIR.rglob("*.conf"):
        try:
            c.chmod(0o640)
        except Exception:
            pass
    for p in INSTALL_DIR.rglob("*.php"):
        try:
            p.chmod(0o640)
        except Exception:
            pass

    # mysql setup
    db_name = input("Database name to create (default: xtream_iptvpro): ").strip() or "xtream_iptvpro"
    db_user = input("Database user to create (default: user_iptvpro): ").strip() or "user_iptvpro"
    db_password = getpass("Password for new database user (leave empty to generate random): ")
    if not db_password:
        db_password = generate_password()
    log(f"Creating DB: {db_name} user: {db_user} (password length {len(db_password)})")

    try:
        configure_mysql_safe(db_name, db_user, db_password)
    except Exception as e:
        log(f"MySQL configuration failed: {e}")
        log("You can create the DB/user manually and re-run the config step.")
        # continue — we still write config but warn user
        if input("Continue and write config file with given DB credentials? (yes/no): ").strip().lower() != "yes":
            sys.exit(1)

    # write config file
    write_config_file_safe(INSTALL_DIR, USER, db_name, db_user, db_password)

    # create systemd service if start script present
    create_systemd_service_if_needed(USER, INSTALL_DIR)

    ip = get_ip()
    log("Installation finished (check logs at %s)" % LOG_FILE)
    log(f"Admin UI (if available) likely: http://{ip}:25500")
    log(f"DB user: {db_user}")
    log(f"DB password: {db_password}")

    print("\nNext steps:")
    print(" - Verify the application admin UI and credentials")
    print(" - Review ownership and permissions of installed files")
    print(" - Replace any 3rd-party download URLs with company mirrors")
    print(" - Monitor CPU/RAM during an initial smoke test")
    print(" - Consider snapshot/backup before going to production")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        log("User cancelled (KeyboardInterrupt)")
    except Exception as e:
        log(f"Fatal error: {e}")
        raise
