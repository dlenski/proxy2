#!/usr/bin/python2
# -*- coding: utf-8 -*-
import sys
import os
import socket
import ssl
import select
import httplib
import urlparse
import threading
import gzip
import zlib
import time
import json
import re
import argparse
import traceback
import xml.etree.ElementTree as ET
from BaseHTTPServer import HTTPServer, BaseHTTPRequestHandler
from SocketServer import ThreadingMixIn
from cStringIO import StringIO
from subprocess import Popen, PIPE
from HTMLParser import HTMLParser
from traceback import format_exc
from binascii import hexlify

def with_color(c, s):
    return "\x1b[%dm%s\x1b[0m" % (c, s)


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    address_family = socket.AF_INET6
    daemon_threads = True

    def handle_error(self, request, client_address):
        # surpress socket/ssl related errors
        cls, e = sys.exc_info()[:2]
        if cls is socket.error or cls is ssl.SSLError:
            pass
        else:
            return HTTPServer.handle_error(self, request, client_address)


class ProxyRequestHandler(BaseHTTPRequestHandler):
    cakey = 'ca.key'
    cacert = 'ca.crt'
    certkey = 'cert.key'
    certdir = 'certs/'
    clientcertdir = 'client_certs/'
    timeout = 30 # don't want to close the sockets faster than GP keepalive
    lock = threading.Lock()

    def __init__(self, *args, **kwargs):
        self.tls = threading.local()
        self.tls.conns = {}

        BaseHTTPRequestHandler.__init__(self, *args, **kwargs)

    def log_error(self, format, *args):
        # surpress "Request timed out: timeout('timed out',)"
        if isinstance(args[0], socket.timeout):
            return

        self.log_message(format, *args)

    def do_CONNECT(self):
        if os.path.isfile(self.cakey) and os.path.isfile(self.cacert) and os.path.isfile(self.certkey) and os.path.isdir(self.certdir):
            self.connect_intercept()
        else:
            print with_color(31, '''Relaying proxy traffic rather than intercepting it.
*** THIS IS PROBABLY NOT WHAT YOU WANT!! ***
You need to create the CA certificate files to allow this proxy to
act as a man-in-the-middle (MITM) to intercept and decode HTTPS
traffic. Run ./setup_https_intercept.sh and restart proxy.''')
            self.connect_relay()

    def connect_intercept(self):
        address = self.path.split(':', 1)
        hostname = address[0]
        address[1] = int(address[1]) or 443
        certpath = "%s/%s.crt" % (self.certdir.rstrip('/'), hostname)

        with self.lock:
            if not os.path.isfile(certpath):
                epoch = "%d" % (time.time() * 1000)
                p1 = Popen(["openssl", "req", "-new", "-key", self.certkey, "-subj", "/CN=%s" % hostname], stdout=PIPE)
                p2 = Popen(["openssl", "x509", "-req", "-days", "3650", "-CA", self.cacert, "-CAkey", self.cakey, "-set_serial", epoch, "-out", certpath], stdin=p1.stdout, stderr=PIPE)
                p2.communicate()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'Connection Established'))
        self.end_headers()

        self.connection = ssl.wrap_socket(self.connection, keyfile=self.certkey, certfile=certpath, server_side=True)
        self.rfile = self.connection.makefile("rb", self.rbufsize)
        self.wfile = self.connection.makefile("wb", self.wbufsize)
        self.address = address

        conntype = self.headers.get('Proxy-Connection', '')
        if conntype.lower() == 'close':
            self.close_connection = 1
        elif (conntype.lower() == 'keep-alive' and self.protocol_version >= "HTTP/1.1"):
            self.close_connection = 0

    def connect_relay(self):
        address = self.path.split(':', 1)
        address[1] = int(address[1]) or 443
        try:
            s = socket.create_connection(address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            print with_color(7, with_color(31, '== Caught exception ==\n%s' % traceback.format_exc()))
            return
        self.send_response(200, 'Connection Established')
        self.end_headers()

        conns = [self.connection, s]
        self.close_connection = 0
        while not self.close_connection:
            rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
            if xlist or not rlist:
                break
            for r in rlist:
                other = conns[1] if r is conns[0] else conns[0]
                data = r.recv(8192)
                if not data:
                    self.close_connection = 1
                    break
                other.sendall(data)

    def do_TUNNEL(self):
        print('Tunnel to: %s' % self.path)
        try:
            s = socket.create_connection(self.address, timeout=self.timeout)
        except Exception as e:
            self.send_error(502)
            print with_color(7, with_color(31, '== Caught exception ==\n%s' % traceback.format_exc()))
            return

        cert_args = {}
        if self.args.cert: cert_args['certfile']=self.args.cert
        if self.args.key: cert_args['keyfile']=self.args.key
        c = ssl.wrap_socket(s, **cert_args)

        c.write('%s %s %s\r\n' % (self.command, self.path, self.request_version))
        for line in self.headers.headers:
            c.write(line.rstrip() + '\r\n')
        c.write('\r\n')
        print("Conveyed %d headers" % len(self.headers))

        with open('tunnel-%s.pcap.txt' % time.strftime('%Y%m%d_%H%M%S'), 'w') as dumpfile:
            print("Dumping to %s" % dumpfile.name)
            dumpfile.write('#run this through text2pcap as: text2pcap -t:%%s -Dn %s %s\n' % (dumpfile.name, dumpfile.name[:-4]))

            conns = [self.connection, c]
            self.close_connection = 0
            while not self.close_connection:
                rlist, wlist, xlist = select.select(conns, [], conns, self.timeout)
                if xlist or not rlist:
                    break
                for r in rlist:
                    other = conns[1] if r is conns[0] else conns[0]
                    data = r.recv(8192)
                    if not data:
                        self.close_connection = 1
                        dumpfile.write('# hangup by '+('client' if r is self.connection else 'server'))
                        break
                    other.sendall(data)

                    print('%s %r' % (('>' if r is self.connection else '<'), hexlify(data)))

                    if data.startswith('\x1a\x2b\x3c\x4d'):
                        # 1a2b3c4d08000034010000000000000045000034
                        # 4 magic (1a2b3c4d), 2 ethertype? (0800), 2 inner packet length? (0034), 8 int64le = 1, inner packet
                        raweth2 = '\0'*12 + data[4:6] + data[16:]

                        dumpfile.write('%s:%d\n' % (('O' if r is self.connection else 'I'), time.time()))
                        dumpfile.write('00000000' + ''.join(' %02x'%ord(b) for b in raweth2) + '\n')
                    else:
                        dumpfile.write('# %r\n' % repr(data))

    def do_GET(self):
        if not getattr(self,'address',None):
            self.send_error(401) # deny proxy requests without a prior CONNECT
            return
        if self.path == 'http://proxy2.test/':
            self.send_cacert()
            return
        elif self.path.startswith(self.args.tunnel_path):
            self.do_TUNNEL()
            return

        req = self
        content_length = int(req.headers.get('Content-Length', 0))
        req_body = self.rfile.read(content_length) if content_length else None

        if req.path[0] == '/':
            if 'Host' not in req.headers:
                req.headers['Host'] = self.address[0] + (":%d"%self.address[1] if self.address[1]!=443 else '')
            if isinstance(self.connection, ssl.SSLSocket):
                req.path = "https://%s%s" % (req.headers['Host'], req.path)
            else:
                req.path = "http://%s%s" % (req.headers['Host'], req.path)

        req_body_modified = self.request_handler(req, req_body)
        if req_body_modified is False:
            self.send_error(403)
            return
        elif req_body_modified is not None:
            req_body = req_body_modified
            req.headers['Content-length'] = str(len(req_body))

        u = urlparse.urlsplit(req.path)
        scheme, netloc, path = u.scheme, u.netloc, (u.path + '?' + u.query if u.query else u.path)
        assert scheme in ('http', 'https')
        if netloc:
            req.headers['Host'] = netloc
        setattr(req, 'headers', self.filter_headers(req.headers))

        try:
            origin = (scheme, netloc)
            if not origin in self.tls.conns:
                if scheme == 'https':
                    cert_args = {}
                    if self.args.cert: cert_args['cert_file']=self.args.cert
                    if self.args.key: cert_args['key_file']=self.args.key
                    self.tls.conns[origin] = httplib.HTTPSConnection(netloc, timeout=self.timeout, **cert_args)
                else:
                    self.tls.conns[origin] = httplib.HTTPConnection(netloc, timeout=self.timeout)
            conn = self.tls.conns[origin]
            conn.request(self.command, path, req_body, dict(req.headers))
            res = conn.getresponse()
            res_body = res.read()
        except Exception as e:
            if origin in self.tls.conns:
                del self.tls.conns[origin]
            self.send_error(502)
            print with_color(7, with_color(31, '== Caught exception ==\n%s' % traceback.format_exc()))
            return

        version_table = {10: 'HTTP/1.0', 11: 'HTTP/1.1'}
        setattr(res, 'headers', res.msg)
        setattr(res, 'response_version', version_table[res.version])

        content_encoding = res.headers.get('Content-Encoding', 'identity')
        res_body_plain = self.decode_content_body(res_body, content_encoding)

        res_body_modified = self.response_handler(req, req_body, res, res_body_plain)
        if res_body_modified is False:
            self.send_error(403)
            return
        elif res_body_modified is not None:
            res_body_plain = res_body_modified
            res_body = self.encode_content_body(res_body_plain, content_encoding)
            res.headers['Content-Length'] = str(len(res_body))

        setattr(res, 'headers', self.filter_headers(res.headers))

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, res.status, res.reason))
        for line in res.headers.headers:
            self.wfile.write(line)
        self.end_headers()
        self.wfile.write(res_body)
        self.wfile.flush()

        with self.lock:
            self.save_handler(req, req_body, res, res_body_plain)

    do_HEAD = do_GET
    do_POST = do_GET
    do_OPTIONS = do_GET

    def filter_headers(self, headers):
        # http://tools.ietf.org/html/rfc2616#section-13.5.1
        hop_by_hop = ('connection', 'keep-alive', 'proxy-authenticate', 'proxy-authorization', 'te', 'trailers', 'transfer-encoding', 'upgrade')
        for k in hop_by_hop:
            del headers[k]

        # accept only supported encodings
        if 'Accept-Encoding' in headers:
            ae = headers['Accept-Encoding']
            filtered_encodings = [x for x in re.split(r',\s*', ae) if x in ('identity', 'gzip', 'x-gzip', 'deflate')]
            headers['Accept-Encoding'] = ', '.join(filtered_encodings)

        return headers

    def encode_content_body(self, text, encoding):
        if encoding == 'identity':
            data = text
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO()
            with gzip.GzipFile(fileobj=io, mode='wb') as f:
                f.write(text)
            data = io.getvalue()
        elif encoding == 'deflate':
            data = zlib.compress(text)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return data

    def decode_content_body(self, data, encoding):
        if encoding == 'identity':
            text = data
        elif encoding in ('gzip', 'x-gzip'):
            io = StringIO(data)
            with gzip.GzipFile(fileobj=io) as f:
                text = f.read()
        elif encoding == 'deflate':
            try:
                text = zlib.decompress(data)
            except zlib.error:
                text = zlib.decompress(data, -zlib.MAX_WBITS)
        else:
            raise Exception("Unknown Content-Encoding: %s" % encoding)
        return text

    def send_cacert(self):
        with open(self.cacert, 'rb') as f:
            data = f.read()

        self.wfile.write("%s %d %s\r\n" % (self.protocol_version, 200, 'OK'))
        self.send_header('Content-Type', 'application/x-x509-ca-cert')
        self.send_header('Content-Length', len(data))
        self.send_header('Connection', 'close')
        self.end_headers()
        self.wfile.write(data)

    def print_info(self, req, req_body, res, res_body):
        def parse_qsl(s):
            return '\n'.join("%-20s %s" % (k, v) for k, v in urlparse.parse_qsl(s, keep_blank_values=True))

        req_header_text = "%s %s %s\n%s" % (req.command, req.path, req.request_version, req.headers)
        res_header_text = "%s %d %s\n%s" % (res.response_version, res.status, res.reason, res.headers)

        print with_color(33, req_header_text)

        u = urlparse.urlsplit(req.path)
        if u.query:
            query_text = parse_qsl(u.query)
            print with_color(32, "==== QUERY PARAMETERS ====\n%s\n" % query_text)

        cookie = req.headers.get('Cookie', '')
        if cookie:
            cookie = parse_qsl(re.sub(r';\s*', '&', cookie))
            print with_color(32, "==== COOKIE ====\n%s\n" % cookie)

        auth = req.headers.get('Authorization', '')
        if auth.lower().startswith('basic'):
            token = auth.split()[1].decode('base64')
            print with_color(31, "==== BASIC AUTH ====\n%s\n" % token)

        if req_body is not None:
            req_body_text = None
            content_type = req.headers.get('Content-Type', '')

            if content_type.startswith('application/x-www-form-urlencoded'):
                req_body_text = parse_qsl(req_body)
            elif content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(req_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        req_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        req_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    req_body_text = req_body
            elif len(req_body) < 1024:
                req_body_text = req_body

            if req_body_text:
                print with_color(32, "==== REQUEST BODY ====\n%s\n" % req_body_text)

        print with_color(36, res_header_text)

        cookies = res.headers.getheaders('Set-Cookie')
        if cookies:
            cookies = '\n'.join(cookies)
            print with_color(31, "==== SET-COOKIE ====\n%s\n" % cookies)

        if res_body is not None:
            res_body_text = None
            content_type = res.headers.get('Content-Type', '')

            if content_type.startswith('application/json'):
                try:
                    json_obj = json.loads(res_body)
                    json_str = json.dumps(json_obj, indent=2)
                    if json_str.count('\n') < 50:
                        res_body_text = json_str
                    else:
                        lines = json_str.splitlines()
                        res_body_text = "%s\n(%d lines)" % ('\n'.join(lines[:50]), len(lines))
                except ValueError:
                    res_body_text = res_body
            elif content_type.startswith('text/html'):
                m = re.search(r'<title[^>]*>\s*([^<]+?)\s*</title>', res_body, re.I)
                if m:
                    h = HTMLParser()
                    print with_color(32, "==== HTML TITLE ====\n%s\n" % h.unescape(m.group(1).decode('utf-8')))
            elif content_type.startswith('text/') and len(res_body) < 1024:
                res_body_text = res_body
            elif content_type.startswith('application/xml') and len(res_body) < 65536:
                res_body_text = res_body

            if res_body_text:
                print with_color(32, "==== RESPONSE BODY ====\n%s\n" % res_body_text)

    def request_handler(self, req, req_body):
        pass

    def response_handler(self, req, req_body, res, res_body):
        ct = res.headers.get('Content-Type','')
        if ct.startswith('application/xml') and res_body.strip().startswith('<'):
            r = ET.fromstring(res_body)
            if r.tag=='policy':
                for entry in r.findall('./gateways/external/list/entry[@name]'):
                    # stupid GP client doesn't know how to resolve the
                    # gateway address while connected through a proxy
                    hp = entry.attrib['name'].split(':', 1)
                    h, p = hp[0], ((':'+hp[1]) if len(hp)==2 else '')
                    entry.attrib['name'] = socket.gethostbyname(h)+p
                return '<?xml version="1.0" encoding="UTF-8"?>' + ET.tostring(r)

    def save_handler(self, req, req_body, res, res_body):
        self.print_info(req, req_body, res, res_body)


def test(HandlerClass=ProxyRequestHandler, ServerClass=ThreadingHTTPServer, protocol="HTTP/1.1"):
    p = argparse.ArgumentParser()
    p.add_argument('-p','--port', type=int, default=8080)
    p.add_argument('-t','--tunnel-path', default='/ssl-tunnel-connect.sslvpn')
    g = p.add_argument_group('Client certificate')
    g.add_argument('--cert', help='PEM file containing client certificate (and optionally private key)')
    g.add_argument('--key', help='PEM file containing client private key (if not included in same file as certificate)')
    args = p.parse_args()
    if args.key and not args.cert:
        p.error("--key without --cert doesn't make sense")

    server_address = ('', args.port)
    HandlerClass.protocol_version = protocol
    HandlerClass.args = args
    httpd = ServerClass(server_address, HandlerClass)

    sa = httpd.socket.getsockname()
    print "Serving HTTP Proxy on", sa[0], "port", sa[1], "..."
    httpd.serve_forever()


if __name__ == '__main__':
    test()
