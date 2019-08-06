import json
import logging
import os
import subprocess
import threading
import time
import datetime
import configparser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path

home = str(Path(os.path.join(str(Path.home()), '.portmon')))
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] [%(levelname)-5.5s]  %(message)s")
rootLogger = logging.getLogger()

fileHandler = logging.FileHandler("{0}/{1}.log".format(home, 'portmon'))
fileHandler.setFormatter(logFormatter)
rootLogger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
rootLogger.addHandler(consoleHandler)
rootLogger.setLevel(logging.INFO)

_FINISH = False


def assert_exit(cond, msg):
    try:
        assert cond
    except AssertionError:
        logging.error('AssertionError of ' + msg)
        global _FINISH
        _FINISH = True


config = configparser.ConfigParser()
config.read(str(Path(os.path.join(home, 'portmon.ini'))))
logging.error(str(Path(os.path.join(home, 'portmon.ini'))))
serve_port = 9000
ports = []
try:
    serve_port = int(config['DEFAULT']['serve_port'])
except Exception as e:
    logging.error('invalid serve_port')
try:
    ports = config['DEFAULT']['monitor_ports'].split(",")
except Exception as e:
    logging.error('invalid monitor_ports')

usage_disk = {}
usage_last = {}

data_file = Path(os.path.join(home, 'data'))
data_path = str(data_file)
if not data_file.is_file():
    logging.debug('no data file')
    with open(data_path, 'w') as fd:
        for p in ports:
            usage_disk[p] = 0
        fd.write(json.dumps(usage_disk))
else:
    logging.debug('exists data file')
    with open(data_path) as fd:
        usage_disk = json.load(fd)


def get_iptable():
    output = subprocess.check_output(['iptables', '-L', '-v', '-n', '-x'])
    return output.decode("utf-8").splitlines()


def add_ports_to_mon(unmoned_ports):
    for p in unmoned_ports:
        assert_exit(isinstance(p, str), 'add_ports_to_mon')
        out = subprocess.check_output(['iptables', '-A', 'OUTPUT', '-p', 'tcp', '--sport', str(p)])
        if out:
            logging.error("add_ports_to_mon fail")


def job():
    interval = 3
    threshold = interval * 60 * 24
    counter = 0
    while True:
        if _FINISH:
            break
        table = get_iptable()

        first = 0
        for i, line in enumerate(table):
            if line.startswith("Chain OUTPUT"):
                first = i + 2

        ofs = 0
        full_outputs_list = []
        if (first + ofs) < len(table):
            while table[first + ofs].strip():
                full_outputs_list.append(table[first + ofs])
                ofs += 1
                if (first + ofs) >= len(table):
                    break

        moned_list = []
        moned_ports = []
        for e in full_outputs_list:
            for p in ports:
                if "spt:" + p in e:
                    moned_list.append(e)
                    moned_ports.append(p)
        unmoned_ports = set(ports) - set(moned_ports)
        logging.debug(unmoned_ports)
        add_ports_to_mon(unmoned_ports)

        usage = {}
        for o in moned_list:
            so = o.split()
            out = so[1]
            port = so[-1][4:]
            assert_exit(isinstance(port, str), '90')
            usage[port] = int(out)

        logging.debug('init usage_disk' + str(usage_disk))
        for port, out in usage.items():
            assert_exit(isinstance(port, str), '94')
            # before reboot
            if out >= usage_disk.get(port, 0):
                logging.debug('out >= usage_disk.get({}, 0)'.format(port))
                usage_disk[port] = out
            # after reboot
            else:
                diff = out - usage_last.get(port, 0)
                usage_disk[port] += diff
                usage_last[port] = out

        with open(data_path, 'w') as fd:
            fd.write(json.dumps(usage_disk))
        logging.debug(usage_disk)

        if counter >= threshold:
            with open(str(data_path + '_daily'), 'a+') as fd:
                fd.write(str(datetime.datetime.now()) + json.dumps(usage_disk) + '\n')
            counter = 0

        counter += interval
        time.sleep(interval)


def get_statistic(port):
    assert_exit(isinstance(port, str), 'get_statistic')
    if not port:
        res = ""
        for p in ports:
            b = usage_disk[p]
            kb = int(b / 1024)
            gb = round(kb / 1024 / 1024, 2)
            rmb = gb
            res += "Port {} data usage: {}KB = {}GB => Bill: {}RMB\n".format(p, kb, gb, rmb)
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
httpd = HTTPServer(('0.0.0.0', serve_port), SimpleHTTPRequestHandler)
httpd.serve_forever()
