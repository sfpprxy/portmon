from http.server import HTTPServer, BaseHTTPRequestHandler
import subprocess


def get_res():
    return subprocess.check_output(['iptables','-L','-v'])


def add_ports_to_mon(unmoned_ports):
    # TODO
    pass


def job():
    ports = [9999, 9998, 9997, 9996, 9995]
    res = get_res()

    # parse
    first = 0
    for i, line in enumerate(res):
        if line.startswith("Chain OUTPUT"):
            first = i + 2

    ofs = 0
    full_outputs_list = []
    while res[first + ofs].strip():
        full_outputs_list.append(res[first + ofs])
        ofs += 1

    outputs_list = []
    moned_ports = []
    for e in full_outputs_list:
        for p in ports:
            if "spt:" + str(p) in e:
                outputs_list.append(e)
                moned_ports.append(p)
    unmoned_ports = set(ports) - set(moned_ports)
    add_ports_to_mon(unmoned_ports)

    usage = {}
    for o in outputs_list:
        so = o.split()
        out = so[1]
        if out[-1] == 'K':
            out = out[:-1]
        port = so[-1][4:]
        usage[port] = out
    print(usage)


    kb = 1024
    gb = round(kb / 1024 / 1024, 3)
    rmb = gb
    return "Data usage: {}KB = {}GB => Bill: {}RMB".format(kb, gb, rmb)


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        paths = {
            '/9999': {'status': 200},
            '/9998': {'status': 200},
            '/9997': {'status': 200},
            '/9996': {'status': 200}
        }

        if self.path in paths:
            self.send_response(200)
            self.end_headers()
            p = self.path
            r = "Hello, {}. {}".format(p, job())
            self.wfile.write(r.encode('utf-8'))
        else:
            self.send_response(404)


httpd = HTTPServer(('0.0.0.0', 9000), SimpleHTTPRequestHandler)
httpd.serve_forever()
