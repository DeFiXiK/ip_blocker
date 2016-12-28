import re
import subprocess
from typing import *

import cmd
import config

BLACKLIST = "blacklist.txt"

IP_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"

def shell(cmdline, *args, **kwargs):
    return subprocess.run(
        args=cmdline.format(*args, **kwargs),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )

def shell_pipe(cmdline, *args, **kwargs):
    return subprocess.Popen(
        args=cmdline.format(*args, **kwargs),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        universal_newlines=True,
    )

def start_dump():
    dump_cmd = shell_pipe(cmd.TCPDUMP, iface=config.IFACE, hostname=config.HOSTNAME)

    for line in dump_cmd.stdout:
        line = line.strip()

        ip_match = re.search(IP_REGEX, line)
        if not ip_match:
            continue

        ip = ip_match.group()
        yield ip


    if dump_cmd.returncode != 0:
        raise RuntimeError(
            "dump cmd returned code {code}, stderr: {stderr}".format(
                code=dump_cmd.returncode,
                stderr=dump_cmd.stderr.read(),
            ))

def iptables_setup():
    for c in [cmd.IPTABLES_CLEAR, cmd.IPTABLES_ADD_BLOCK_RULE]:
        cmd_complete = shell(c)
        if cmd_complete.returncode != 0:
            raise RuntimeError(
                "\"{cmdline}\" returned code {code}, stderr: {stderr}".format(
                    cmdline=c,
                    code=cmd_complete.returncode,
                    stderr=cmd_complete.stderr,
                ))

def read_blacklist():
    with open(BLACKLIST) as f:
        rawlist = f.readlines()

    blacklist = []
    for line in rawlist:
        line = line.strip()
        if line.startswith('#'):
            continue
        line = line.replace('*', '')
        blacklist.append(line)

    return blacklist

def block_ip(ip):
    check_cmd = shell(cmd.IPSET_CHECK, ip=ip)

    if "NOT" not in check_cmd.stderr:
        return

    block_cmd = shell(cmd.IPSET_ADD, ip=ip)

    if block_cmd.returncode != 0:
        raise RuntimeError(
            "block cmd returned code {code}, stderr: {stderr}".format(
                code=block_cmd.returncode,
                stderr=block_cmd.stderr,
            ))

def main():
    print("Читаю {}...".format(BLACKLIST))
    blacklist = read_blacklist()
    print("Найдено {} правил".format(len(blacklist)))

    print("Настраиваю iptables...")
    iptables_setup()

    print("Запускаю dump в дочернем процессе...")
    dump_gen = start_dump()

    for ip in dump_gen:
        if any([ ip.startswith(mask) for mask in blacklist ]):
            print("Блокирую {}".format(ip))
            block_ip(ip)

if __name__ == '__main__':
    main()
