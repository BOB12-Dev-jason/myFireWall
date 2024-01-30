import subprocess
import re

def get_conntrack_info():
    command = "sudo conntrack -L -c ESTABLISHED | tail -n 5"
    result = subprocess.run(command, shell=True, capture_output=True, text=True).stdout.split('\n')

    infos = []
    pattern = r'(\w+)\s+\d+\s+\d+\s+\w+\s+src=(\S+)\s+dst=(\S+)\s+sport=(\d+)\s+dport=(\d+)'

    for line in result:
        match = re.search(pattern, line)
        if match:
            infos.append(match.groups())
    
    return infos


def get_iptables_info():
    command = "sudo iptables -nvL"
    result = subprocess.run(command, shell=True, capture_output=True, text=True).stdout.split('\n')

    infos = []

    pattern = r"\s+0\s+0\s+(\S+)\s+(\S+)\s+--\s+\*\s+\*\s+(\S+)\s+(\S+/\d+)"
    for line in result:
        match = re.search(pattern, line)
        if match:
            infos.append(match.groups())
    
    return infos
