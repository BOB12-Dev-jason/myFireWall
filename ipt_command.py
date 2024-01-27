import subprocess

def set_iptables_rules(params):
    command = ["sudo", "iptables", "-A", "FORWARD"] + params
    print("set_rule cmd:", command)
    subprocess.run(command)


def get_iptables_rules():
    command = "sudo iptables -nvL"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    print(result.stdout)

def get_iptable_logs():
    logs = subprocess.check_output(["dmesg"]).decode("utf-8")
    print(logs)

# def clear_iptable_rules():
#     command = "iptables -F FORWARD"
#     subprocess.run(command)

# command1 = "sudo iptables -nvL"
# command2 = "sudo iptables -A FORWARD -p tcp --dport 80 -j DROP"
# command3 = "sudo iptables -F FORWARD"
# command4 = "sudo iptables -D FORWARD -p tcp --dport 80 -j DROP"
# command5 = "sudo iptables -A FORWARD -p tcp --dport 80 -j LOG --log-prefix 'MYDROP: ' --log-level 4"
# dmesg_cmd = "dmesg -T --tail 5"

params1 = ["-p", "tcp", "--dport", "80", "-j", "LOG", "--log-prefix", "'MYDROP: '", "--log-level", "4"]
params2 = ["-p", "tcp", "--dport", "80", "-j", "DROP"]
set_iptables_rules(params1)
set_iptables_rules(params2)
get_iptables_rules()
get_iptable_logs()
# clear_iptable_rules()

