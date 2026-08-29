#!/usr/bin/env python3
from http.server import BaseHTTPRequestHandler, HTTPServer
FRAG = {'a':'CMO{', 'FA24':'Th3y_', 'R*':'L1K3_', '243kopa':'T0_', 'F*^&':'h1d3}'}
class S(BaseHTTPRequestHandler):
    def do_GET(self):
        k = self.headers.get('X-Fragment-Key', '')
        body = FRAG.get(k, '').encode()
        print('  [srv] UA=%r key=%r -> %r' % (self.headers.get('User-Agent'), k, body), flush=True)
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a): pass
HTTPServer(('127.0.0.1', 5566), S).serve_forever()
