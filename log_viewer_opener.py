import os
from http.server import HTTPServer, SimpleHTTPRequestHandler

# Ottieni la directory del file corrente
current_dir = os.path.dirname(os.path.abspath(__file__))

# Cambia la directory di lavoro a quella padre
os.chdir(current_dir)

# Configura il server
host = 'localhost'  # Indirizzo del server
port = 8000         # Porta del server

class CustomHTTPRequestHandler(SimpleHTTPRequestHandler):
    """Handler personalizzato se serve personalizzazione (opzionale)."""
    pass

# Avvia il server HTTP
httpd = HTTPServer((host, port), CustomHTTPRequestHandler)
print(f"HTTP server started on http://{host}:{port}/")
print(f"Follow this URL, then click on log_viewer.html to see requests log")

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\nServer interrotto.")
    httpd.server_close()