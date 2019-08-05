import os
import json
import logging
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
import subprocess
from pathlib import Path


# TODO read ports from conf file
ports = ['9999', '9998', '9997', '9996', '9995']
usage_disk = {}
usage_last = {}

data_file = Path(os.path.join(os.getcwd(), 'data'))
data_path = str(data_file)
if not data_file.is_file():
    with open(data_path, 'w') as fd:
        for p in ports:
            usage_disk[p] = 0
        fd.write(json.dumps(usage_disk))
else:
    with open(data_path) as fd:
        usage_disk = json.load(fd)


def get_iptable():
    output = b'Chain INPUT (policy ACCEPT 16763734 packets, 16357775418 bytes)\n    pkts      bytes target     prot opt in     out     source               destination         \n    5975   407369 f2b-sshd   tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            multiport dports 4422\n\nChain FORWARD (policy DROP 0 packets, 0 bytes)\n    pkts      bytes target     prot opt in     out     source               destination         \n       0        0 DOCKER-USER  all  --  *      *       0.0.0.0/0            0.0.0.0/0           \n       0        0 DOCKER-ISOLATION  all  --  *      *       0.0.0.0/0            0.0.0.0/0           \n       0        0 ACCEPT     all  --  *      docker0  0.0.0.0/0            0.0.0.0/0            ctstate RELATED,ESTABLISHED\n       0        0 DOCKER     all  --  *      docker0  0.0.0.0/0            0.0.0.0/0           \n       0        0 ACCEPT     all  --  docker0 !docker0  0.0.0.0/0            0.0.0.0/0           \n       0        0 ACCEPT     all  --  docker0 docker0  0.0.0.0/0            0.0.0.0/0           \n\nChain OUTPUT (policy ACCEPT 12281260 packets, 15806068588 bytes)\n    pkts      bytes target     prot opt in     out     source               destination         \n 8688709 11148015386            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:9999\n 1500556 4274300891            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:9998\n      22     1092            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:9997\n\nChain DOCKER (1 references)\n    pkts      bytes target     prot opt in     out     source               destination         \n\nChain DOCKER-ISOLATION (1 references)\n    pkts      bytes target     prot opt in     out     source               destination         \n       0        0 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0           \n\nChain DOCKER-USER (1 references)\n    pkts      bytes target     prot opt in     out     source               destination         \n       0        0 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0           \n\nChain f2b-sshd (1 references)\n    pkts      bytes target     prot opt in     out     source               destination         \n    5975   407369 RETURN     all  --  *      *       0.0.0.0/0            0.0.0.0/0           \n'
    # output = subprocess.check_output(['iptables', '-L', '-v', '-n', '-x'])
    return output.decode("utf-8").splitlines()
    # with open('/Users/joe/Dropbox/Work/portmon/ipval') as fp:
    #     return fp.readlines()


def add_ports_to_mon(unmoned_ports):
    # for p in unmoned_ports:
    #     out = subprocess.check_output(['iptables', '-A', 'OUTPUT', '-p', 'tcp', '--sport', str(p)])
    #     if out:
    #         logging.error("add_ports_to_mon fail")
    pass


def job():
    while True:
        table = get_iptable()

        first = 0
        for i, line in enumerate(table):
            if line.startswith("Chain OUTPUT"):
                first = i + 2

        ofs = 0
        full_outputs_list = []
        while table[first + ofs].strip():
            full_outputs_list.append(table[first + ofs])
            ofs += 1

        moned_list = []
        moned_ports = []
        for e in full_outputs_list:
            for p in ports:
                if "spt:" + p in e:
                    moned_list.append(e)
                    moned_ports.append(p)
        unmoned_ports = set(ports) - set(moned_ports)
        add_ports_to_mon(unmoned_ports)

        usage = {}
        for o in moned_list:
            so = o.split()
            out = so[1]
            port = so[-1][4:]
            usage[port] = int(out)

        for port, out in usage.items():
            last = usage_last.get(port, 0)
            if out < last:
                usage_last[port] = out
            if last == 0:
                usage_last[port] = usage_disk[port]
            else:
                diff = out - last
                usage_disk[port] += diff
                usage_last[port] = out

        with open(data_path, 'w') as fd:
            fd.write(json.dumps(usage_disk))
        time.sleep(60)


def get_statistic(port):
    if not port:
        res = ""
        for p in ports:
            b = usage_disk[port]
            kb = int(b / 1024)
            gb = round(kb / 1024 / 1024, 2)
            rmb = gb
            res += "Port {} data usage: {}KB = {}GB => Bill: {}RMB\n".format(port, kb, gb, rmb)
        return res
    b = usage_disk[port]
    kb = int(b / 1024)
    gb = round(kb / 1024 / 1024, 2)
    rmb = gb
    return "Port {} data usage: {}KB = {}GB => Bill: {}RMB".format(port, kb, gb, rmb)


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    paths = {
        '/': {'status': 200}
    }
    for p in ports:
        paths['/' + p] = {'status': 200}

    def do_GET(self):
        if self.path in self.paths:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(get_statistic(self.path[1:]).encode('utf-8'))
        else:
            self.send_response(404)


jobt = threading.Thread(target=job, name='TrafficMonitorThread')
jobt.start()
httpd = HTTPServer(('0.0.0.0', 9000), SimpleHTTPRequestHandler)
httpd.serve_forever()
