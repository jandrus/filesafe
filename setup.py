#!/usr/bin/python
#
# Filesafe - Secure file vault
# Copyright (C) 2023 James Andrus
# Email: jandrus@citadel.edu

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


""" Filesafe server setup """


import os
import time
import configparser
import ipaddress


HOME            = os.path.expanduser("~")
FILESAFE_DIR    = f"{HOME}/.config/filesafe/"
BANNER          = """
    _______ __                ____
   / ____(_) /__  _________ _/ __/__
  / /_  / / / _ \/ ___/ __ `/ /_/ _ \\
 / __/ / / /  __(__  ) /_/ / __/  __/
/_/   /_/_/\___/____/\__,_/_/  \___/
"""


def clear_screen():
    """ Clear terminal """
    os.system("clear")

def print_banner(section):
    """ Print banner """
    clear_screen()
    print(BANNER)
    print(f"Setup: [{section}]")

def create_dirs():
    """ Create filesafe directories """
    os.makedirs(FILESAFE_DIR, exist_ok=True)
    print("Filesafe directories created")

def should_create_new():
    """ Create new config file """
    configuration_file = f"{FILESAFE_DIR}filesafe.ini"
    server_section = {}
    should_continue = True
    if os.path.isfile(configuration_file):
        print_banner("CONF FILE DETECTED")
        print("Previous configuration file exists. All previous CLIENT settings will be erased (SERVER settings will be preserved).")
        ans = input("Create new config (y/n): ").lower()
        if ans[0] == "y":
            print("Creating new configuration file.")
            config = configparser.ConfigParser(allow_no_value=True)
            config.read(configuration_file)
            os.remove(configuration_file)
            time.sleep(1.5)
            if "SERVER" in config.sections():
                server_section = dict(config["SERVER"])
        else:
            should_continue = False
            print(f"Please edit \'{configuration_file}\' manually.")
            time.sleep(1.5)
    return server_section, should_continue

def setup_conf_file():
    """ Setup conf file """
    server_conf, should_continue = should_create_new()
    if not should_continue:
        return
    conf_file = f"{FILESAFE_DIR}filesafe.ini"
    conf = configparser.ConfigParser(allow_no_value=True)
    conf.read(conf_file)
    if "CLIENT" not in conf.sections():
        conf.add_section("CLIENT")
    conf.set("CLIENT", "server_port", get_port())
    print("Port [OK]")
    time.sleep(1.5)
    conf.set("CLIENT", "server_ip", get_ip())
    print("IP [OK]")
    time.sleep(1.5)
    if server_conf:
        conf.add_section("SERVER")
        conf.set("SERVER", "# Directory that filesafe will lock and unlock.")
        conf.set("SERVER", "# This directory MUST exist at run time.")
        conf.set("SERVER", "protected_dir", server_conf["protected_dir"])
        conf.set("SERVER", "# Time (in minutes) where server will automatically lock the protected directory.")
        conf.set("SERVER", "timeout", server_conf["timeout"])
        conf.set("SERVER", "# Auto-backup frequency.")
        conf.set("SERVER", "# Valid options are: \'n\' (NO automatic backups), \'d\' (Daily backups), or \'w\' (Weekly backups)")
        conf.set("SERVER", "auto_backup_freq", server_conf["auto_backup_freq"])
        conf.set("SERVER", "# Time of day (24Hour clock) where automatic backup will occur")
        conf.set("SERVER", "#   Valid time format examples: 0000, 0400, 1302, 2400, 0000 (2400 == 0000)")
        conf.set("SERVER", "auto_backup_time", server_conf["auto_backup_time"])
        conf.set("SERVER", "# Auto backup day of the week.")
        conf.set("SERVER", "# Valid options are 1 - 7. Only valid if auto_backup_freq is set to \'w\'.")
        conf.set("SERVER", "# 1 equates to moday and 7 equates to sunday.")
        conf.set("SERVER", "auto_backup_day", server_conf["auto_backup_day"])
        conf.set("SERVER", "# Secondary backup directory. Auto backups and prompted backups will be copied to this directory.")
        conf.set("SERVER", "# Primary directory for backups will still be \'~/.config/filesafe/backup\'.")
        conf.set("SERVER", "# Provide valid full directory or \'n\' for none. This directory MUST exist at run time.")
        conf.set("SERVER", "sec_backup_dir", server_conf["sec_backup_dir"])
    with open(conf_file, 'w', encoding="us-ascii") as fp:
        conf.write(fp)
    print(f"Config file saved to \'{FILESAFE_DIR}filesafe.ini\'")
    time.sleep(2)

def get_ip():
    """ Get server ip """
    try:
        print_banner("server_ip")
        ip_addr = input("Enter server's ip address: ")
        _ip_test = ipaddress.ip_address(ip_addr)
        return ip_addr
    except ValueError:
        print("Invalid ip")
        time.sleep(1.5)
        return get_ip()

def get_port():
    """ Get port for server """
    try:
        print_banner("server_port")
        port = int(input("Enter port number for filesafe server: "))
        if 0 < port < 65535:
            return str(port)
        print("Invalid port")
        time.sleep(1.5)
        return get_port()
    except ValueError:
        print("Invalid port")
        time.sleep(1.5)
        return get_port()


create_dirs()
setup_conf_file()
print_banner("Complete")
