#!/usr/bin/python3
# -*- coding: utf-8 -*-
import subprocess, os, random, string, sys, shutil, socket, zipfile, urllib.request
from itertools import cycle
from zipfile import ZipFile
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError
import base64
import time

rDownloadURL = {"main": "https://bitbucket.org/emre1393/xtreamui_mirror/downloads/main_xtreamcodes_reborn.tar.gz", "sub": "https://bitbucket.org/emre1393/xtreamui_mirror/downloads/sub_xtreamcodes_reborn.tar.gz"}
rPackages = ["libcurl3", "libxslt1-dev", "libgeoip-dev", "e2fsprogs", "wget", "mcrypt", "nscd", "htop", "zip", "unzip", "mc", "libjemalloc1", "python-paramiko", "mysql-server"]
rInstall = {"MAIN": "main", "LB": "sub"}
rUpdate = {"UPDATE": "update"}
rMySQLCnf = base64.b64decode("IyBYdHJlYW0gQ29kZXMKCltjbGllbnRdCnBvcnQgICAgICAgICAgICA9IDMzMDYKCltteXNxbGRfc2FmZV0KbmljZSAgICAgICAgICAgID0gMAoKW215c3FsZF0KdXNlciAgICAgICAgICAgID0gbXlzcWwKcG9ydCAgICAgICAgICAgID0gNzk5OQpiYXNlZGlyICAgICAgICAgPSAvdXNyCmRhdGFkaXIgICAgICAgICA9IC92YXIvbGliL215c3FsCnRtcGRpciAgICAgICAgICA9IC90bXAKbGMtbWVzc2FnZXMtZGlyID0gL3Vzci9zaGFyZS9teXNxbApza2lwLWV4dGVybmFsLWxvY2tpbmcKc2tpcC1uYW1lLXJlc29sdmU9MQoKYmluZC1hZGRyZXNzICAgICAgICAgICAgPSAqCmtleV9idWZmZXJfc2l6ZSA9IDEyOE0KCm15aXNhbV9zb3J0X2J1ZmZlcl9zaXplID0gNE0KbWF4X2FsbG93ZWRfcGFja2V0ICAgICAgPSA2NE0KbXlpc2FtLXJlY292ZXItb3B0aW9ucyA9IEJBQ0tVUAptYXhfbGVuZ3RoX2Zvcl9zb3J0X2RhdGEgPSA4MTkyCnF1ZXJ5X2NhY2hlX2xpbWl0ICAgICAgID0gNE0KcXVlcnlfY2FjaGVfc2l6ZSAgICAgICAgPSAyNTZNCgoKZXhwaXJlX2xvZ3NfZGF5cyAgICAgICAgPSAxMAptYXhfYmlubG9nX3NpemUgICAgICAgICA9IDEwME0KCm1heF9leGVjdXRpb25fdGltZSA9IDAKdHJhbnNhY3Rpb25faXNvbGF0aW9uID0gUkVBRC1DT01NSVRURUQKCm1heF9jb25uZWN0aW9ucyAgPSAyMDAwMApiYWNrX2xvZyA9IDQwOTYKb3Blbl9maWxlc19saW1pdCA9IDIwMjQwCmlubm9kYl9vcGVuX2ZpbGVzID0gMjAyNDAKbWF4X2Nvbm5lY3RfZXJyb3JzID0gMzA3Mgp0YWJsZV9vcGVuX2NhY2hlID0gNDA5Ngp0YWJsZV9kZWZpbml0aW9uX2NhY2hlID0gNDA5NgoKCnRtcF90YWJsZV9zaXplID0gMUcKbWF4X2hlYXBfdGFibGVfc2l6ZSA9IDFHCgppbm5vZGJfYnVmZmVyX3Bvb2xfc2l6ZSA9IDEwRwppbm5vZGJfYnVmZmVyX3Bvb2xfaW5zdGFuY2VzID0gMTAKaW5ub2RiX3JlYWRfaW9fdGhyZWFkcyA9IDY0Cmlubm9kYl93cml0ZV9pb190aHJlYWRzID0gNjQKaW5ub2RiX3RocmVhZF9jb25jdXJyZW5jeSA9IDAKaW5ub2RiX2ZsdXNoX2xvZ19hdF90cnhfY29tbWl0ID0gMAppbm5vZGJfZmx1c2hfbWV0aG9kID0gT19ESVJFQ1QKcGVyZm9ybWFuY2Vfc2NoZW1hID0gMAppbm5vZGItZmlsZS1wZXItdGFibGUgPSAxCmlubm9kYl9pb19jYXBhY2l0eT0yMDAwMAppbm5vZGJfdGFibGVfbG9ja3MgPSAwCmlubm9kYl9sb2NrX3dhaXRfdGltZW91dCA9IDEwMAppbm5vZGJfZGVhZGxvY2tfZGV0ZWN0ID0gMAoKCnNxbC1tb2RlPSJOT19FTkdJTkVfU1VCU1RJVFVUSU9OIgoKW215c3FsZHVtcF0KcXVpY2sKcXVvdGUtbmFtZXMKbWF4X2FsbG93ZWRfcGFja2V0ICAgICAgPSAyNE0KY29tcGxldGUtaW5zZXJ0CgpbbXlzcWxdCgpbaXNhbWNoa10Ka2V5X2J1ZmZlcl9zaXplICAgICAgICAgICAgICA9IDE2TQ==").decode('utf-8')
rMySQLServiceFile = base64.b64decode("IyBNeVNRTCBzeXN0ZW1kIHNlcnZpY2UgZmlsZQoKW1VuaXRdCkRlc2NyaXB0aW9uPU15U1FMIENvbW11bml0eSBTZXJ2ZXIKQWZ0ZXI9bmV0d29yay50YXJnZXQKCltJbnN0YWxsXQpXYW50ZWRCeT1tdWx0aS11c2VyLnRhcmdldAoKW1NlcnZpY2VdClR5cGU9Zm9ya2luZwpVc2VyPW15c3FsCkdyb3VwPW15c3FsClBJREZpbGU9L3J1bi9teXNxbGQvbXlzcWxkLnBpZApQZXJtaXNzaW9uc1N0YXJ0T25seT10cnVlCkV4ZWNTdGFydFByZT0vdXNyL3NoYXJlL215c3FsL215c3FsLXN5c3RlbWQtc3RhcnQgcHJlCkV4ZWNTdGFydD0vdXNyL3NiaW4vbXlzcWxkIC0tZGFlbW9uaXplIC0tcGlkLWZpbGU9L3J1bi9teXNxbGQvbXlzcWxkLnBpZCAtLW1heC1leGVjdXRpb24tdGltZT0wCkVudmlyb25tZW50RmlsZT0tL2V0Yy9teXNxbC9teXNxbGQKVGltZW91dFNlYz02MDAKUmVzdGFydD1vbi1mYWlsdXJlClJ1bnRpbWVEaXJlY3Rvcnk9bXlzcWxkClJ1bnRpbWVEaXJlY3RvcnlNb2RlPTc1NQpMaW1pdE5PRklMRT01MDAw").decode('utf-8')

class col:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    YELLOW = '\033[33m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def generate(length=19): 
    return ''.join(random.choice(string.ascii_letters + string.digits) for i in range(length))

def getIP():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        s.close()
        return "127.0.0.1"

def getVersion():
    try: 
        result = subprocess.check_output("lsb_release -d".split(), stderr=subprocess.DEVNULL)
        return result.decode('utf-8').split(":")[-1].strip()
    except Exception: 
        return ""

def printc(rText, rColour=col.OKBLUE, rPadding=0):
    print("%s ┌──────────────────────────────────────── %s" % (rColour, col.ENDC))
    for i in range(rPadding): 
        print("%s │                                          │ %s" % (rColour, col.ENDC))
    print("%s │ %s%s%s │ %s" % (rColour, " "*(20-(len(rText)//2)), rText, " "*(40-(20-(len(rText)//2))-len(rText)), col.ENDC))
    for i in range(rPadding): 
        print("%s │                                          │ %s" % (rColour, col.ENDC))
    print("%s └──────────────────────────────────────── %s" % (rColour, col.ENDC))
    print(" ")

def prepare(rType="MAIN"):
    global rPackages
    if rType != "MAIN": 
        rPackages = rPackages[:-3]
    printc("Preparing Installation")
    for rFile in ["/var/lib/dpkg/lock-frontend", "/var/cache/apt/archives/lock", "/var/lib/dpkg/lock"]:
        try: 
            os.remove(rFile)
        except: 
            pass
    os.system("apt-get update > /dev/null")
    printc("Removing libcurl4 if installed")
    os.system("apt-get remove --auto-remove libcurl4 -y > /dev/null")
    
    # Install packages
    for rPackage in rPackages:
        printc("Installing %s" % rPackage)
        os.system("apt-get install %s -y > /dev/null" % rPackage)
    
    # Handle libpng12 for newer Ubuntu versions
    printc("Installing libpng")
    # Try to create symbolic link for newer versions
    os.system("apt-get install libpng16-16 -y > /dev/null")
    os.system("ln -sf /usr/lib/x86_64-linux-gnu/libpng16.so.16 /usr/lib/x86_64-linux-gnu/libpng12.so.0 2>/dev/null")
    
    # Alternative method for libpng12
    if not os.path.exists("/usr/lib/x86_64-linux-gnu/libpng12.so.0"):
        os.system("wget -q -O /tmp/libpng12.deb http://mirrors.kernel.org/ubuntu/pool/main/libp/libpng/libpng12-0_1.2.54-1ubuntu1_amd64.deb")
        os.system("dpkg -i /tmp/libpng12.deb > /dev/null 2>&1")
        try: 
            os.remove("/tmp/libpng12.deb")
        except: 
            pass
    
    # Fix apt if needed
    os.system("apt-get install -f -y > /dev/null")
    
    try:
        subprocess.check_output("getent passwd xtreamcodes > /dev/null", shell=True)
    except:
        # Create User
        printc("Creating user xtreamcodes")
        os.system("adduser --system --shell /bin/false --group --disabled-login xtreamcodes > /dev/null")
    if not os.path.exists("/home/xtreamcodes"): 
        os.mkdir("/home/xtreamcodes")
    return True

def install(rType="MAIN"):
    global rInstall, rDownloadURL
    printc("Downloading Software")
    try: 
        rURL = rDownloadURL[rInstall[rType]]
    except:
        printc("Invalid download URL!", col.FAIL)
        return False
    os.system('wget -q -O "/tmp/xtreamcodes.tar.gz" "%s"' % rURL)
    if os.path.exists("/tmp/xtreamcodes.tar.gz"):
        printc("Installing Software")
        os.system('tar -zxvf "/tmp/xtreamcodes.tar.gz" -C "/home/xtreamcodes/" > /dev/null')
        try: 
            os.remove("/tmp/xtreamcodes.tar.gz")
        except: 
            pass
        return True
    printc("Failed to download installation file!", col.FAIL)
    return False

def update(rType="MAIN"):
    if rType == "UPDATE":
        printc("Enter the link of release_xyz.zip file:", col.WARNING)
        rlink = input('Example: https://lofertech.com/xui/release_22f.zip\n\nNow enter the link:\n\n')
    else:
        rlink = "https://lofertech.com/xui/release_22f.zip"
        printc("Installing Admin Panel")
    hdr = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/84.0.4147.125 Safari/537.36',
       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
       'Accept-Charset': 'ISO-8859-1,utf-8;q=0.7,*;q=0.3',
       'Accept-Encoding': 'none',
       'Accept-Language': 'en-US,en;q=0.8',
       'Connection': 'keep-alive'}
    req = urllib.request.Request(rlink, headers=hdr)
    try:
        urllib.request.urlopen(req)
    except:
        printc("Invalid download URL!", col.FAIL)
        return False
    rURL = rlink
    printc("Downloading Software Update")  
    os.system('wget -q -O "/tmp/update.zip" "%s"' % rURL)
    if os.path.exists("/tmp/update.zip"):
        try: 
            is_ok = zipfile.ZipFile("/tmp/update.zip")
            is_ok.close()
        except:
            printc("Invalid link or zip file is corrupted!", col.FAIL)
            try:
                os.remove("/tmp/update.zip")
            except:
                pass
            return False
        printc("Updating Software")
        os.system('chattr -i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null && rm -rf /home/xtreamcodes/iptv_xtream_codes/admin > /dev/null && rm -rf /home/xtreamcodes/iptv_xtream_codes/pytools > /dev/null && unzip /tmp/update.zip -d /tmp/update/ > /dev/null && cp -rf /tmp/update/XtreamUI-master/* /home/xtreamcodes/iptv_xtream_codes/ > /dev/null && rm -rf /tmp/update/XtreamUI-master > /dev/null && rm -rf /tmp/update > /dev/null && wget -q https://bitbucket.org/emre1393/xtreamui_mirror/downloads/GeoLite2.mmdb -O /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null && chown -R xtreamcodes:xtreamcodes /home/xtreamcodes/ > /dev/null && chmod +x /home/xtreamcodes/iptv_xtream_codes/permissions.sh > /dev/null && chattr +i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null')
        
        # Check if permissions.sh exists before reading
        permissions_file = "/home/xtreamcodes/iptv_xtream_codes/permissions.sh"
        try:
            with open(permissions_file, 'r') as f:
                content = f.read()
            if "sudo chmod 400 /home/xtreamcodes/iptv_xtream_codes/config" not in content:
                raise FileNotFoundError
        except (FileNotFoundError, IOError):
            permissions_script = """#!/bin/bash
sudo chmod -R 777 /home/xtreamcodes 2>/dev/null
sudo find /home/xtreamcodes/iptv_xtream_codes/admin/ -type f -exec chmod 644 {} \\; 2>/dev/null
sudo find /home/xtreamcodes/iptv_xtream_codes/admin/ -type d -exec chmod 755 {} \\; 2>/dev/null
sudo find /home/xtreamcodes/iptv_xtream_codes/wwwdir/ -type f -exec chmod 644 {} \\; 2>/dev/null
sudo find /home/xtreamcodes/iptv_xtream_codes/wwwdir/ -type d -exec chmod 755 {} \\; 2>/dev/null
sudo chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx/sbin/nginx 2>/dev/null
sudo chmod +x /home/xtreamcodes/iptv_xtream_codes/nginx_rtmp/sbin/nginx_rtmp 2>/dev/null
sudo chmod 400 /home/xtreamcodes/iptv_xtream_codes/config 2>/dev/null"""
            with open('/home/xtreamcodes/iptv_xtream_codes/permissions.sh', 'w') as f:
                f.write(permissions_script)
        
        os.system("sed -i 's|xtream-ui.com/install/balancer.py|github.com/emre1393/xtreamui_mirror/raw/master/balancer.py|g' /home/xtreamcodes/iptv_xtream_codes/pytools/balancer.py")
        os.system("/home/xtreamcodes/iptv_xtream_codes/permissions.sh > /dev/null")
        try: 
            os.remove("/tmp/update.zip")
        except: 
            pass
        return True
    printc("Failed to download installation file!", col.FAIL)
    return False

def mysql(rUsername, rPassword):
    global rMySQLCnf
    printc("Configuring MySQL")
    
    # Start MySQL service first
    printc("Starting MySQL service")
    os.system("systemctl start mysql > /dev/null 2>&1")
    os.system("service mysql start > /dev/null 2>&1")
    
    # Wait for MySQL to start
    time.sleep(5)
    
    rCreate = True
    if os.path.exists("/etc/mysql/my.cnf"):
        try:
            with open("/etc/mysql/my.cnf", "r") as f:
                content = f.read(14)
            if content == "# Xtream Codes": 
                rCreate = False
        except Exception:
            pass
    if rCreate:
        try:
            shutil.copy("/etc/mysql/my.cnf", "/etc/mysql/my.cnf.xc")
        except Exception:
            pass
        with open("/etc/mysql/my.cnf", "w") as rFile:
            rFile.write(rMySQLCnf)
        os.system("systemctl restart mysql > /dev/null 2>&1")
        os.system("service mysql restart > /dev/null 2>&1")
        time.sleep(5)
    
    printc("Enter MySQL Root Password:", col.WARNING)
    for i in range(5):
        rMySQLRoot = input("  ")
        print(" ")
        if len(rMySQLRoot) > 0: 
            rExtra = " -p%s" % rMySQLRoot
        else: 
            rExtra = ""
        printc("Drop existing & create database? Y/N", col.WARNING)
        if input("  ").upper() == "Y": 
            rDrop = True
        else: 
            rDrop = False
        try:
            # Test MySQL connection first
            test_cmd = f'mysql -u root{rExtra} -e "SELECT 1;" > /dev/null 2>&1'
            if os.system(test_cmd) != 0:
                raise Exception("MySQL connection failed")
                
            if rDrop:
                os.system('mysql -u root%s -e "DROP DATABASE IF EXISTS xtream_iptvpro; CREATE DATABASE IF NOT EXISTS xtream_iptvpro;" > /dev/null' % rExtra)
                os.system("mysql -u root%s xtream_iptvpro < /home/xtreamcodes/iptv_xtream_codes/database.sql > /dev/null" % rExtra)
                os.system('mysql -u root%s -e "USE xtream_iptvpro; UPDATE settings SET live_streaming_pass = \'%s\', unique_id = \'%s\', crypt_load_balancing = \'%s\', get_real_ip_client=\'\';" > /dev/null' % (rExtra, generate(20), generate(10), generate(20)))
                os.system('mysql -u root%s -e "USE xtream_iptvpro; REPLACE INTO streaming_servers (id, server_name, domain_name, server_ip, vpn_ip, ssh_password, ssh_port, diff_time_main, http_broadcast_port, total_clients, system_os, network_interface, latency, status, enable_geoip, geoip_countries, last_check_ago, can_delete, server_hardware, total_services, persistent_connections, rtmp_port, geoip_type, isp_names, isp_type, enable_isp, boost_fpm, http_ports_add, network_guaranteed_speed, https_broadcast_port, https_ports_add, whitelist_ips, watchdog_data, timeshift_only) VALUES (1, \'Main Server\', \'\', \'%s\', \'\', NULL, NULL, 0, 25461, 1000, \'%s\', \'eth0\', 0, 1, 0, \'\', 0, 0, \'{}\', 3, 0, 25462, \'low_priority\', \'\', \'low_priority\', 0, 1, \'\', 1000, 25463, \'\', \'[\"127.0.0.1\",\"\"]\', \'{}\', 0);" > /dev/null' % (rExtra, getIP(), getVersion()))
                
                # Create admin user with proper escaping - using subprocess instead of os.system
                admin_cmd = [
                    "mysql", "-u", "root", "-p" + rMySQLRoot if rMySQLRoot else "", "-e",
                    "USE xtream_iptvpro; REPLACE INTO reg_users (id, username, password, email, member_group_id, verified, status) VALUES (1, 'admin', '$6$rounds=20000$xtreamcodes$XThC5OwfuS0YwS4ahiifzF14vkGbGsFF1w7ETL4sRRC5sOrAWCjWvQJDromZUQoQuwbAXAFdX3h3Cp3vqulpS0', 'admin@website.com', 1, 1, 1);"
                ]
                if not rMySQLRoot:
                    admin_cmd.remove("-p")
                
                try:
                    subprocess.run(admin_cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
                except:
                    # Fallback to simple method if subprocess fails
                    os.system('mysql -u root%s -e "USE xtream_iptvpro; INSERT INTO reg_users (id, username, password, email, member_group_id, verified, status) VALUES (1, \'admin\', \'admin\', \'admin@website.com\', 1, 1, 1) ON DUPLICATE KEY UPDATE username=\'admin\';" > /dev/null' % rExtra)
                
                os.system('mysql -u root%s -e "CREATE USER \'%s\'@\'%%\' IDENTIFIED BY \'%s\'; GRANT ALL PRIVILEGES ON xtream_iptvpro.* TO \'%s\'@\'%%\' WITH GRANT OPTION; GRANT SELECT, LOCK TABLES ON *.* TO \'%s\'@\'%%\';FLUSH PRIVILEGES;" > /dev/null' % (rExtra, rUsername, rPassword, rUsername, rUsername))
                os.system('mysql -u root%s -e "USE xtream_iptvpro; CREATE TABLE IF NOT EXISTS dashboard_statistics (id int(11) NOT NULL AUTO_INCREMENT, type varchar(16) NOT NULL DEFAULT \'\', time int(16) NOT NULL DEFAULT \'0\', count int(16) NOT NULL DEFAULT \'0\', PRIMARY KEY (id)) ENGINE=InnoDB DEFAULT CHARSET=latin1; INSERT INTO dashboard_statistics (type, time, count) VALUES(\'conns\', UNIX_TIMESTAMP(), 0),(\'users\', UNIX_TIMESTAMP(), 0);" > /dev/null' % rExtra)
                
                if not os.path.exists("/etc/mysql/mysqld"):
                    try:
                        with open("/lib/systemd/system/mysql.service", "r") as f:
                            service_content = f.read()
                        if "EnvironmentFile=-/etc/mysql/mysqld" not in service_content:
                            os.system('echo "LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libjemalloc.so.1" > /etc/mysql/mysqld')
                            with open("/lib/systemd/system/mysql.service", "w") as f:
                                f.write(rMySQLServiceFile)
                            os.system('systemctl daemon-reload; systemctl restart mysql.service;')
                    except Exception:
                        pass
            try: 
                os.remove("/home/xtreamcodes/iptv_xtream_codes/database.sql")
            except: 
                pass
            return True
        except Exception: 
            printc("Invalid password or MySQL connection failed! Try again", col.FAIL)
    return False

def encrypt(rHost="127.0.0.1", rUsername="user_iptvpro", rPassword="", rDatabase="xtream_iptvpro", rServerID=1, rPort=7999):
    printc("Encrypting...")
    try: 
        os.remove("/home/xtreamcodes/iptv_xtream_codes/config")
    except: 
        pass
    
    config_data = '{\"host\":\"%s\",\"db_user\":\"%s\",\"db_pass\":\"%s\",\"db_name\":\"%s\",\"server_id\":\"%d\", \"db_port\":\"%d\"}' % (rHost, rUsername, rPassword, rDatabase, rServerID, rPort)
    key = '5709650b0d7806074842c6de575025b1'
    
    # Ensure both strings are the same length by cycling the key
    key_cycled = ''.join(key[i % len(key)] for i in range(len(config_data)))
    
    # XOR encryption
    encrypted = ''.join(chr(ord(c) ^ ord(k)) for c, k in zip(config_data, key_cycled))
    
    # Encode to base64
    encrypted_b64 = base64.b64encode(encrypted.encode('latin-1')).decode('ascii')
    
    with open('/home/xtreamcodes/iptv_xtream_codes/config', 'w') as rf:
        rf.write(encrypted_b64)

def configure(rType):
    printc("Configuring System")
    
    # Check and update /etc/fstab
    try:
        with open("/etc/fstab", "r") as f:
            fstab_content = f.read()
        if "/home/xtreamcodes/iptv_xtream_codes/" not in fstab_content:
            with open("/etc/fstab", "a") as rFile:
                rFile.write("tmpfs /home/xtreamcodes/iptv_xtream_codes/streams tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=90% 0 0\ntmpfs /home/xtreamcodes/iptv_xtream_codes/tmp tmpfs defaults,noatime,nosuid,nodev,noexec,mode=1777,size=2G 0 0")
    except Exception:
        pass
    
    # Check and update /etc/sudoers
    try:
        with open("/etc/sudoers", "r") as f:
            sudoers_content = f.read()
        if "xtreamcodes" not in sudoers_content:
            os.system('echo "xtreamcodes ALL = (root) NOPASSWD: /sbin/iptables, /usr/bin/chattr" >> /etc/sudoers')
    except Exception:
        pass
    
    # Create init script
    if not os.path.exists("/etc/init.d/xtreamcodes"):
        with open("/etc/init.d/xtreamcodes", "w") as rFile:
            rFile.write("#! /bin/bash\n/home/xtreamcodes/iptv_xtream_codes/start_services.sh")
        os.system("chmod +x /etc/init.d/xtreamcodes > /dev/null")
    
    # Remove existing ffmpeg link
    try: 
        os.remove("/usr/bin/ffmpeg")
    except: 
        pass
    
    if rType == "MAIN": 
        # edited these 2 files return api response without main server ip, it is useful if you use a proxy in front of your main server.
        os.system("mv /home/xtreamcodes/iptv_xtream_codes/wwwdir/panel_api.php /home/xtreamcodes/iptv_xtream_codes/wwwdir/.panel_api_original.php && wget -q https://bitbucket.org/emre1393/xtreamui_mirror/downloads/panel_api.php -O /home/xtreamcodes/iptv_xtream_codes/wwwdir/panel_api.php")
        os.system("mv /home/xtreamcodes/iptv_xtream_codes/wwwdir/player_api.php /home/xtreamcodes/iptv_xtream_codes/wwwdir/.player_api_original.php && wget -q https://bitbucket.org/emre1393/xtreamui_mirror/downloads/player_api.php -O /home/xtreamcodes/iptv_xtream_codes/wwwdir/player_api.php")
    
    # Create tv_archive directory
    if not os.path.exists("/home/xtreamcodes/iptv_xtream_codes/tv_archive"): 
        os.makedirs("/home/xtreamcodes/iptv_xtream_codes/tv_archive/", exist_ok=True)
    
    # Create symbolic link for ffmpeg
    os.system("ln -s /home/xtreamcodes/iptv_xtream_codes/bin/ffmpeg /usr/bin/")
    
    # Download and setup GeoLite2 database
    os.system("chattr -i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null")
    os.system("wget -q https://bitbucket.org/emre1393/xtreamui_mirror/downloads/GeoLite2.mmdb -O /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb")
    os.system("wget -q https://bitbucket.org/emre1393/xtreamui_mirror/downloads/pid_monitor.php -O /home/xtreamcodes/iptv_xtream_codes/crons/pid_monitor.php")
    
    # Set permissions
    os.system("chown xtreamcodes:xtreamcodes -R /home/xtreamcodes > /dev/null")
    os.system("chmod -R 0777 /home/xtreamcodes > /dev/null")
    os.system("chattr +i /home/xtreamcodes/iptv_xtream_codes/GeoLite2.mmdb > /dev/null")
    os.system("sed -i 's|chown -R xtreamcodes:xtreamcodes /home/xtreamcodes|chown -R xtreamcodes:xtreamcodes /home/xtreamcodes 2>/dev/null|g' /home/xtreamcodes/iptv_xtream_codes/start_services.sh")
    os.system("chmod +x /home/xtreamcodes/iptv_xtream_codes/start_services.sh > /dev/null")
    os.system("mount -a")
    os.system("chmod 0700 /home/xtreamcodes/iptv_xtream_codes/config > /dev/null")
    os.system("sed -i 's|echo \"Xtream Codes Reborn\";|header(\"Location: https://www.google.com/\");|g' /home/xtreamcodes/iptv_xtream_codes/wwwdir/index.php")
    
    # Update /etc/hosts
    try:
        with open("/etc/hosts", "r") as f:
            hosts_content = f.read()
        
        hosts_entries = [
            ("127.0.0.1    api.xtream-codes.com", "api.xtream-codes.com"),
            ("127.0.0.1    downloads.xtream-codes.com", "downloads.xtream-codes.com"),
            ("127.0.0.1    xtream-codes.com", "xtream-codes.com")
        ]
        
        for entry, check in hosts_entries:
            if check not in hosts_content:
                os.system(f'echo "{entry}" >> /etc/hosts')
    except Exception:
        pass
    
    # Update crontab
    try:
        with open("/etc/crontab", "r") as f:
            crontab_content = f.read()
        if "@reboot root /home/xtreamcodes/iptv_xtream_codes/start_services.sh" not in crontab_content:
            os.system('echo "@reboot root /home/xtreamcodes/iptv_xtream_codes/start_services.sh" >> /etc/crontab')
    except Exception:
        pass

def start(first=True):
    if first: 
        printc("Starting Xtream Codes")
    else: 
        printc("Restarting Xtream Codes")
    os.system("/home/xtreamcodes/iptv_xtream_codes/start_services.sh > /dev/null")

def modifyNginx():
    printc("Modifying Nginx")
    rPath = "/home/xtreamcodes/iptv_xtream_codes/nginx/conf/nginx.conf"
    
    try:
        with open(rPath, "r") as f:
            rPrevData = f.read()
        
        if "listen 25500;" not in rPrevData:
            shutil.copy(rPath, "%s.xc" % rPath)
            nginx_config = """    server {
        listen 25500;
        index index.php index.html index.htm;
        root /home/xtreamcodes/iptv_xtream_codes/admin/;

        location ~ \\.php$ {
            limit_req zone=one burst=8;
            try_files $uri =404;
            fastcgi_index index.php;
            fastcgi_pass php;
            include fastcgi_params;
            fastcgi_buffering on;
            fastcgi_buffers 96 32k;
            fastcgi_buffer_size 32k;
            fastcgi_max_temp_file_size 0;
            fastcgi_keep_conn on;
            fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
            fastcgi_param SCRIPT_NAME $fastcgi_script_name;
        }
    }
}"""
            rData = "}".join(rPrevData.split("}")[:-1]) + nginx_config
            with open(rPath, "w") as rFile:
                rFile.write(rData)
    except Exception as e:
        printc(f"Error modifying Nginx config: {str(e)}", col.FAIL)

if __name__ == "__main__":
    printc("Xtream UI - Installer Mirror", col.OKGREEN, 2)
    print("%s │ NOTE: this is a forked mirror of original installer from emre1393/xtream-ui.com %s" % (col.OKGREEN, col.ENDC))
    print("%s │ Paid Service On Telegram @lofertech & Youtube = LoferTech Official. %s" % (col.OKGREEN, col.ENDC))
    print("%s │ For more information visit lofertech.com %s" % (col.OKGREEN, col.ENDC))
    print(" ")
    rType = input("  Installation Type [MAIN, LB, UPDATE]: ")
    print(" ")
    
    if rType.upper() in ["MAIN", "LB"]:
        if rType.upper() == "LB":
            rHost = input("  Main Server IP Address: ")
            rPassword = input("  MySQL Password: ")
            try: 
                rServerID = int(input("  Load Balancer Server ID: "))
            except: 
                rServerID = -1
            print(" ")
        else:
            rHost = "127.0.0.1"
            rPassword = generate()
            rServerID = 1
            
        rUsername = "user_iptvpro"
        rDatabase = "xtream_iptvpro"
        rPort = 7999
        
        if len(rHost) > 0 and len(rPassword) > 0 and rServerID > -1:
            printc("Start installation? Y/N", col.WARNING)
            if input("  ").upper() == "Y":
                print(" ")
                try:
                    rRet = prepare(rType.upper())
                    if not install(rType.upper()): 
                        sys.exit(1)
                    if rType.upper() == "MAIN":
                        if not mysql(rUsername, rPassword): 
                            sys.exit(1)
                    encrypt(rHost, rUsername, rPassword, rDatabase, rServerID, rPort)
                    configure(rType.upper())
                    if rType.upper() == "MAIN": 
                        modifyNginx()
                        update(rType.upper())
                    start()
                    printc("Installation completed!", col.OKGREEN, 2)
                    if rType.upper() == "MAIN":
                        printc("Please store your MySQL password!")
                        printc(rPassword)
                        printc("Admin UI: http://%s:25500" % getIP())
                        printc("Admin UI default login is admin/admin")
                except Exception as e:
                    printc(f"Installation failed: {str(e)}", col.FAIL)
                    sys.exit(1)
            else: 
                printc("Installation cancelled", col.FAIL)
        else: 
            printc("Invalid entries", col.FAIL)
            
    elif rType.upper() == "UPDATE":
        if os.path.exists("/home/xtreamcodes/iptv_xtream_codes/wwwdir/api.php"):
            printc("Update Admin Panel? Y/N?", col.WARNING)
            if input("  ").upper() == "Y":
                try:
                    if not update(rType.upper()): 
                        sys.exit(1)
                    printc("Installation completed!", col.OKGREEN, 2)
                    start(False)
                except Exception as e:
                    printc(f"Update failed: {str(e)}", col.FAIL)
                    sys.exit(1)
        else: 
            printc("Install Xtream Codes Main first!", col.FAIL)
    else: 
        printc("Invalid installation type", col.FAIL)
