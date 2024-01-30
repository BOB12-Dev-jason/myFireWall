from flask import Flask, render_template, request, redirect
import subprocess

import myutils as ut

app = Flask(__name__)

blocked_ips = []


@app.route("/")
def home():
    return render_template("index.html", iptables_info=ut.get_iptables_info() ,blocked_ips=blocked_ips, conn_info=ut.get_conntrack_info())


@app.route("/delete_rule/<protocol>/<sip>/<target>", methods=["POST"])
def delete_rule(protocol, sip, target):
    dip = request.form.get('dip')
    command = f"sudo iptables -D FORWARD -s {sip} -d {dip} -p {protocol} -m conntrack --ctstate NEW,ESTABLISHED -j {target}"
    print(command)
    subprocess.run(command, shell=True)
    return redirect("/")


@app.route("/block_ip", methods=["POST"])
def block_ip():
    ip_to_block = request.form.get("ip")
    print("IP 차단:", ip_to_block)
    blocked_ips.append(ip_to_block)

    command = f"sudo iptables -A FORWARD -s {ip_to_block} -m conntrack --ctstate NEW,ESTABLISHED -j DROP"
    subprocess.run(command, shell=True)

    return redirect("/")


@app.route("/unblock_ip/<ip>", methods=["POST"])
def unblock_ip(ip):
    blocked_ips.remove(ip)

    command = f"sudo iptables -D FORWARD -s {ip} -j DROP"
    subprocess.run(command, shell=True)

    return redirect("/")


@app.route("/search_ip/<search_ip>", methods=["GET"])
def search_ip(search_ip):
    return redirect("/")


@app.route("/remove_connect/<protocol>/<sport>/<dport>", methods=["POST"])
def remove_connect(protocol, sport, dport):
    command = f"sudo conntrack -D -p {protocol} --sport {sport} --dport {dport}"

    subprocess.run(command, shell=True)

    return redirect("/")






if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)

