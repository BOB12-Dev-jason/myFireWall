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

    for line in result:
        words = line.split()
        if len(words) > 7 and words[0].isdigit() and words[1].isdigit():
            infos.append((words[2], words[3], words[7], words[8])) # target, protocol, src, dst
    
    print(infos)
    return infos


def get_dmesg_logs(keyword=""):
    print("keyword:", keyword)
    if keyword=="":
        command = "sudo dmesg -T | tail -n 10"
    else:
        command = f"sudo dmesg -T | tail -n 10 | grep {keyword}"

    result = subprocess.run(command, shell=True, capture_output=True, text=True).stdout.split('\n')

    return result
