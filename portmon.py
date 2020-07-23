import json
import logging
import os
import subprocess
import threading
import time
import datetime
import configparser
from pathlib import Path

home = str(Path(os.path.join(str(Path.home()), '.portmon')))
logFormatter = logging.Formatter("%(asctime)s [%(threadName)-12.12s] {%(pathname)s:%(lineno)d} "
                                 "[%(levelname)-5.5s]  %(message)s")
rootLogger = logging.getLogger()

fileHandler = logging.FileHandler("{0}/{1}.log".format(home, 'portmon'))
fileHandler.setFormatter(logFormatter)
rootLogger.addHandler(fileHandler)

consoleHandler = logging.StreamHandler()
consoleHandler.setFormatter(logFormatter)
rootLogger.addHandler(consoleHandler)
rootLogger.setLevel(logging.DEBUG)

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
logging.info("config path: " + str(Path(os.path.join(home, 'portmon.ini'))))
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

try:
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
except Exception as e:
    logging.error(e, exc_info=True)


def get_iptable():
    output = subprocess.check_output(['iptables', '-L', '-v', '-n', '-x'])
    return output.decode("utf-8").splitlines()


def parse_iptable():
    """
    :return in text form:
     8686487 11140954791            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:9999
     1499833  4273724219            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:9998
          22        1092            tcp  --  *      *       0.0.0.0/0            0.0.0.0/0            tcp spt:9997
    """
    table = get_iptable()
    first = 0

    for i, line in enumerate(table):
        if line.startswith("Chain OUTPUT"):
            first = i + 2

    offset = 0
    full_outputs_list = []
    if (first + offset) < len(table):
        while table[first + offset].strip():
            full_outputs_list.append(table[first + offset])
            offset += 1
            if (first + offset) >= len(table):
                break
    return full_outputs_list


def add_ports_to_mon(unmoned_ports):
    for p in unmoned_ports:
        assert_exit(isinstance(p, str), 'add_ports_to_mon')
        out = subprocess.check_output(['iptables', '-A', 'OUTPUT', '-p', 'tcp', '--sport', str(p)])
        if out:
            logging.error("add_ports_to_mon fail")


def job():
    interval = 60
    threshold = interval * 60 * 24
    counter = 0
    while True:
        if _FINISH:
            break
        full_outputs_list = parse_iptable()
        # parse full_outputs_list
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
        # parse monitored list
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
        # backup data daily
        if counter >= threshold:
            with open(str(data_path + '_daily'), 'a+') as fd:
                fd.write(str(datetime.datetime.now()) + json.dumps(usage_disk) + '\n')
            counter = 0
        counter += interval
        time.sleep(interval)


def get_statistic(port):
    logging.info("get_statistic of " + str(port))
    assert_exit(isinstance(port, str), 'get_statistic')
    if (not port) or (not port in ports):
        res = ""
        for p in ports:
            b = usage_disk[p]
            kb = int(b / 1024)
            gb = round(kb / 1024 / 1024, 2)
            rmb = gb
            res += "Port {} data usage: {}KB = {}GB => Bill: {}RMB\n".format(p, kb, gb, rmb)
        logging.info(res)
        return res
    b = usage_disk[port]
    kb = int(b / 1024)
    gb = round(kb / 1024 / 1024, 2)
    rmb = gb
    res = "Port {} data usage: {}KB = {}GB => Bill: {}RMB".format(port, kb, gb, rmb)
    logging.info(res)
    return res


try:
    import sys
    sys.path.insert(0, '/usr/bin/bottle')

    from bottle import route, run

    jobt = threading.Thread(target=job, name='TrafficMonitorThread')
    jobt.start()

    @route('/')
    def index():
        return get_statistic('')

    @route('/<port>')
    def port(port):
        return get_statistic(port)

    run(host='0.0.0.0', port=serve_port)
except Exception as e:
    logging.error(e, exc_info=True)
