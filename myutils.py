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


# def check_rules(rules):
#     rule_set = []

#     for i in range(len(rules)):
#         if i==0:
#             rule_set.append((rules[i], "yes"))

#         current_rule = (rules[i][1], rules[i][2], rules[i][3])

#         for j in range(i+1, len(rules)):
#             next_rule = (rules[j][1], rules[j][2], rules[j][3])
#             print("next_rule", next_rule)

#             if current_rule == next_rule: # protocol, src, dst가 같다면
#                 if rules[i][0] == 'DROP':
#                     rule_set.append((rules[j], "no"))
#                 else:
#                     rule_set.append((rules[j], "yes"))
    
#     print(rule_set)


def get_iptables_info():
    command = "sudo iptables -nvL"
    result = subprocess.run(command, shell=True, capture_output=True, text=True).stdout.split('\n')

    infos = []

    for line in result:
        words = line.split()
        if len(words) > 7 and words[0].isdigit() and words[1].isdigit():
            infos.append((words[2], words[3], words[7], words[8])) # target, protocol, src, dst
    
    print(infos)
    #  check_rules(infos)
    return infos


def get_dmesg_logs(keyword=""):
    print("keyword:", keyword)
    if keyword=="":
        command = "sudo dmesg -T | tail -n 10"
    else:
        command = f"sudo dmesg -T | tail -n 10 | grep {keyword}"

    result = subprocess.run(command, shell=True, capture_output=True, text=True).stdout.split('\n')

    return result


