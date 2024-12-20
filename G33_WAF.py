from http.server import BaseHTTPRequestHandler, HTTPServer 
import argparse, os, sys, requests, re
from socketserver import ThreadingMixIn
from datetime import datetime
import threading

def merge_two_dicts(x, y):
    return x | y

def set_header():
    headers = {
        'Host': hostname
    }
    return headers

log_path = os.path.abspath(os.path.join(os.path.dirname(__file__), 'log.txt'))

class ProxyHTTPRequestHandler(BaseHTTPRequestHandler):

    protocol_version = 'HTTP/1.0'

    def is_sql_injection(self, payload):
        sql_patterns = [
         r"(\bUNION\b\s+SELECT|\bSELECT\b\s+.*\bFROM\b|\bINSERT\b\s+INTO\b|\bDELETE\b\s+FROM\b|\bUPDATE\b\s+SET\b)",  #Questi pattern identificano l'inserimento di comandi SQL nella query passata dal client, che potrebbero essere tentativi di danneggiare il database
         r"('.*?'\s+OR\s+'.*?=.*?')",  # Pattern che rileva l'utilizzo di uguaglianze sempre vere, usate per bypassare i controlli di autenticazione e ottenere l'accesso a risorse protette
         r"(--|#|\b/\*|\*/)", # Questi pattern identificano la presenza di commenti SQL utilizzati dagli attaccanti per terminare prematuramente la query preimpostata e inserire codice dannoso
         r"(\bOR\b\s+\d+=\d+|\bAND\b\s+\d+=\d+)", #Pattern che rilevano l'uso di operatori logici per manipolare la query
         r"(\%27|\%22|\%3D|\%3B|\%2D)",  #Questo pattern identifica la presenza di caratteri URL encoded, tecnica sofisticata utilizzata per evitare rilevamenti facili
         r"(\bCHAR\b\s*\(\s*\d+\s*\))", #Rileva attacco di tipo CHAR(x)
         r"(\bCONCAT\b\s*\(\s*\w+\s*,\s*\w+\))",  # Rileva l'uso di CONCAT per concatenare stringhe
         r"(;)",  # Pattern che rileva l'utilizzo di un terminatore di query
        ]
        threat = False
        for pattern in sql_patterns:
         if re.search(pattern, payload, re.IGNORECASE) is not None:
             threat = True
             return threat

        return threat

    def is_xss_attack(self, payload):
        xss_patterns = [
         r"<.*?script.*?>",               # Cattura qualsiasi tag HTML che contiene "script" all'interno
         r"(\bon\w+\s*=\s*(['\"].*?['\"]|.*?))",  # Eventi HTML (ad esempio, onclick, onload) seguiti da un valore
         r"((javascript|vbscript|data):.*)",       # URI che utilizzano schemi per eseguire codice
         r"<.*?(iframe|object|embed|form|link).*?>",  # Tag HTML potenzialmente pericolosi
         r"(\balert\b|\bprompt\b|\bconfirm\b)"    # Funzioni JavaScript comuni negli attacchi XSS 
        ]

        threat = False
        for pattern in xss_patterns:
            if re.search(pattern, payload, re.IGNORECASE) is not None:
                threat = True
                return threat

        return threat

    def filter_traffic(self, body=False):
        threat=0
        for key, value in self.parse_query_string().items():
            if self.is_sql_injection(value):
                threat=1
                return threat
            if self.is_xss_attack(value):
                threat=2
                return threat

        for key, value in self.headers.items():
            if self.is_xss_attack(value):
                threat=2
                return threat

        if body and 'content-length' in self.headers:
            content_len = int(self.headers.get('content-length', 0))
            if content_len > 0:
                post_body = self.rfile.read(content_len).decode('utf-8')
                if self.is_sql_injection(post_body):
                    threat=1
                    return threat
                if self.is_xss_attack(post_body):
                   threat=2
                   return threat

        return threat

    def parse_query_string(self):
        from urllib.parse import parse_qs, urlparse
        query = urlparse(self.path).query

        return {k: v[0] for k, v in parse_qs(query).items()}

    def do_HEAD(self):
        self.do_GET(body=False)
        return

    def do_GET(self, body=True):
        sent = False
        try:
            threat=self.filter_traffic(body)
            if threat==1:
                self.log_traffic(threat,403)
                print (datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " Blocked suspicious HTTP request")
                self.send_error(403, "Blocked by WAF: SQL injection detected")
                return
            elif threat==2:
                self.log_traffic(threat,403)
                print (datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " Blocked suspicious HTTP request")
                self.send_error(403, "Blocked by WAF: XSS attack detected")
                return
            elif threat==0:
             url = f'https://{hostname}{self.path}'
             req_header = self.parse_headers()
             resp = requests.get(url, headers=merge_two_dicts(req_header, set_header()), verify=False)
             sent = True
             self.send_response(resp.status_code)
             self.send_resp_headers(resp)
             msg = resp.text
             self.log_traffic(threat,resp.status_code)

             if body:
                  self.wfile.write(msg.encode(encoding='UTF-8', errors='strict'))
                  print (datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " HTTP request served")
            return
        finally:
            if (not sent) and (threat ==0):
             self.log_traffic(threat, 404)
             self.send_error(404, 'Error trying to proxy')

    def do_POST(self, body=True):
        sent = False
        try:
            threat = self.filter_traffic(body)
            if threat==1:
                self.log_traffic(threat,403)
                print (datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " Blocked suspicious HTTP request")
                self.send_error(403, "Blocked by WAF: SQL injection detected")
                return
            elif threat==2:
                self.log_traffic(threat,403)
                print (datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " Blocked suspicious HTTP request")
                self.send_error(403, "Blocked by WAF: XSS attack detected")
                return
            elif threat ==0: 
             url = f'https://{hostname}{self.path}'
             content_len = int(self.headers.get('content-length', 0))
             post_body = self.rfile.read(content_len)
             req_header = self.parse_headers()
             resp = requests.post(url, data=post_body, headers=merge_two_dicts(req_header, set_header()), verify=False)
             sent = True
             self.send_response(resp.status_code)
             self.send_resp_headers(resp)
             self.log_traffic(threat,resp.status_code)

             if body:
                 self.wfile.write(resp.content)
                 print (datetime.now().strftime("%Y-%m-%d %H:%M:%S") + " Served HTTP request")
            return
        finally:
            if not sent:
                self.log_traffic(threat, 404)
                self.send_error(404, 'Error trying to proxy')
    
    def log_traffic(self, threat, status_code):
        message = "No threat detected"
        if threat==1:
            message="SQL injection"
        elif threat==2:
            message="XSS attack"

        with open(log_path, "a") as f:
            f.write(datetime.now().strftime("%Y-%m-%d %H:%M:%S") + f"; IP: {self.client_address[0]}; Method: {self.command}; URL: {self.path}; Minaccia rilevata: {message}; Status_Code: {status_code} \n")
        with open(log_path, "r+") as f:
         lines = f.readlines()  

         if len(lines) > 0 and len(lines) < 1000:

            lines = lines[-1000:]
            f.seek(0) 
            f.writelines(lines)  
            f.truncate()

    def parse_headers(self):
        req_header = {}
        for line in self.headers:
            line_parts = [o.strip() for o in line.split(':', 1)]
            if len(line_parts) == 2:
                req_header[line_parts[0]] = line_parts[1]
        return req_header

    def send_resp_headers(self, resp):
        respheaders = resp.headers
        for key in respheaders:
            if key not in ['Content-Encoding', 'Transfer-Encoding', 'content-encoding', 'transfer-encoding', 'content-length', 'Content-Length']:
                self.send_header(key, respheaders[key])

        self.send_header('Content-Length', len(resp.content))
        self.end_headers()

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    prova = "prova"

def parse_args():
    parser = argparse.ArgumentParser(description='Proxy HTTP requests')
    parser.add_argument('--port', dest='port', type=int, default=9999,
                        help='serve HTTP requests on specified port (default: random)')
    parser.add_argument('--hostname', dest='hostname', type=str, default='en.wikipedia.org',
                        help='hostname to be processed (default: en.wikipedia.org)')
    args = parser.parse_args(sys.argv[1:])
    return args

if __name__ == "__main__":
    args = parse_args()
    hostname = args.hostname
    print(f"HTTP server is starting on 127.0.0.1, port {args.port}...")
    print("Run log_viewer_opener.py to see requests log") 

    server_thread = threading.Thread(
        target=lambda: ThreadedHTTPServer(('0.0.0.0', args.port), ProxyHTTPRequestHandler).serve_forever()
    )
    server_thread.start()