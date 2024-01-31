from flask import Flask, render_template, request, redirect
import subprocess

import nfqueue as nfq
import myutils as ut

app = Flask(__name__)

blocked_ips = []
system_logs = ut.get_dmesg_logs()
log_search_keyword = ''
webfw_status = "활성화"

@app.route("/")
def home():
    return render_template("index.html", 
                           iptables_info = ut.get_iptables_info(),
                           blocked_ips = blocked_ips,
                           conn_info = ut.get_conntrack_info(),
                           logs = system_logs,
                           log_search_keyword = log_search_keyword,
                           webfw_status = webfw_status)


@app.route("/add_rule", methods=["POST"])
def add_rule():
    index = request.form.get('index')
    protocol = request.form.get('protocol')

    sip1, sip2, sip3, sip4 = request.form.get('sip1'), request.form.get('sip2'), request.form.get('sip3'), request.form.get('sip4')
    smask = request.form.get('smask')
    sip = f"{sip1}.{sip2}.{sip3}.{sip4}/{smask}"

    dip1, dip2, dip3, dip4 = request.form.get('dip1'), request.form.get('dip2'), request.form.get('dip3'), request.form.get('dip4')
    dmask = request.form.get('dmask')
    dip = f"{dip1}.{dip2}.{dip3}.{dip4}/{dmask}"

    target = request.form.get('target')
    replace = request.form.get('replace')

    logPrefix = request.form.get('logPrefix')
    logLevel = request.form.get('logLevel')

    if target=="LOG":
        if replace == 'n':
            command = f"sudo iptables -I FORWARD {index} -s {sip} -d {dip} -j LOG --log-prefix '{logPrefix} ' --log-level {logLevel}"
        elif replace == 'y':
            command = f"sudo iptables -R FORWARD {index} -s {sip} -d {dip} -j LOG --log-prefix '{logPrefix} ' --log-level {logLevel}"
    else:
        if replace == 'n':
            command = f"sudo iptables -I FORWARD {index} -s {sip} -d {dip} -p {protocol} -m conntrack --ctstate NEW,ESTABLISHED -j {target}"
        elif replace == 'y':
            command = f"sudo iptables -R FORWARD {index} -s {sip} -d {dip} -p {protocol} -m conntrack --ctstate NEW,ESTABLISHED -j {target}"
    
    print("add_rule command:",command)
    subprocess.run(command, shell=True)
    return redirect("/")


@app.route("/delete_rule/<index>", methods=["POST"])
def delete_rule(index):
    command = f"sudo iptables -D FORWARD {index}"

    print("delete_rule command:",command)
    subprocess.run(command, shell=True)
    return redirect("/")


@app.route("/block_ip", methods=["POST"])
def block_ip():
    ip_to_block = request.form.get("ip")
    print("IP 차단:", ip_to_block)
    blocked_ips.append(ip_to_block)

    command = f"sudo iptables -A FORWARD -s {ip_to_block} -m conntrack --ctstate NEW,ESTABLISHED -j DROP"
    log_command = f"sudo iptables -A FORWARD -s {ip_to_block} -j LOG --log-prefix 'IP_DROP: ' --log-level 4"
    print("block_ip command:", command + '\n' + log_command)
    
    subprocess.run(log_command, shell=True)
    subprocess.run(command, shell=True)

    return redirect("/")


@app.route("/unblock_ip/<ip>", methods=["POST"])
def unblock_ip(ip):
    blocked_ips.remove(ip)

    command = f"sudo iptables -D FORWARD -s {ip} -m conntrack --ctstate NEW,ESTABLISHED -j DROP"
    log_command = f"sudo iptables -D FORWARD -s {ip} -j LOG --log-prefix 'DROP: ' --log-level 4"
    print("unblock_ip command:", command + '\n' + log_command)
    subprocess.run(command, shell=True)
    subprocess.run(log_command, shell=True)

    return redirect("/")


@app.route("/active_webfw", methods=["GET"])
def active_webfw():
    global webfw_status
    status = request.form.get("status")
    print(status)
    if status == "active":
        command = "iptables -A FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0"
        webfw_status = "비활성화"
        nfq.bindQueue()
    else:
        command = "iptables -D FORWARD -p tcp --dport 80 -j NFQUEUE --queue-num 0"
        webfw_status = "활성화"
        nfq.unbindQueue()
    subprocess.run(command, shell=True)
    
    # webfw_status = status
    return redirect("/")


@app.route("/search_ip/<search_ip>", methods=["GET"])
def search_ip(search_ip):
    return redirect("/")


@app.route("/remove_connect/<protocol>/<sport>/<dport>", methods=["POST"])
def remove_connect(protocol, sport, dport):
    command = f"sudo conntrack -D -p {protocol} --sport {sport} --dport {dport}"

    subprocess.run(command, shell=True)

    return redirect("/")


@app.route("/search_logs", methods=["POST"])
def search_logs():
    global system_logs, log_search_keyword
    keyword = request.form.get('keyword')
    print("keyword:", keyword)
    system_logs = ut.get_dmesg_logs(keyword)
    log_search_keyword = keyword
    return redirect("/")




if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

