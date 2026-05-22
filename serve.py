import os, http.server, socketserver
os.chdir(os.path.dirname(os.path.abspath(__file__)))
handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", 4200), handler) as httpd:
    httpd.serve_forever()
