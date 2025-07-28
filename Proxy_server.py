import http.server
import socketserver
from urllib.parse import urlparse, parse_qs
import urllib.request
import joblib
import re
import warnings
from sklearn.exceptions import InconsistentVersionWarning

# Suppress sklearn version warning
warnings.filterwarnings("ignore", category=InconsistentVersionWarning)

# Load the ML model
model = joblib.load("training_model.pkl")
print("✅ Model loaded successfully.")

PORT = 8080

class ProxyHTTPRequestHandler(http.server.BaseHTTPRequestHandler):

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"<h1>Welcome to Web Application Firewall Proxy</h1>")
            return

        # Expected format: /proxy_route/domain.com/path?params
        if self.path.startswith("/proxy_route/"):
            try:
                target = self.path[len("/proxy_route/"):]
                url = f"http://{target}"
                parsed_url = urlparse(url)

                # Feature extraction for ML model
                features = extract_features(parsed_url.path + "?" + (parsed_url.query or ""))
                result = model.predict([features])

                # Log the request
                print(f"🔍 Scanning URL: {url}")
                if result[0] == 1:
                    print("🚫 Intrusion Detected!")
                    with open("intrusion_log.txt", "a") as f:
                        f.write(f"Blocked: {url}\n")
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b"403 Forbidden: Intrusion Detected")
                    return

                # Forward request to actual server
                with urllib.request.urlopen(url) as response:
                    content = response.read()
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(content)

            except Exception as e:
                print("❌ Proxy error:", e)
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"500 Internal Server Error")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")

    def do_POST(self):
        # Very basic POST handler, extracts and forwards
        if self.path.startswith("/proxy_route/"):
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)

                target = self.path[len("/proxy_route/"):]
                url = f"http://{target}"
                parsed_url = urlparse(url)

                # Feature extraction
                features = extract_features(parsed_url.path + "?" + post_data.decode())
                result = model.predict([features])

                print(f"🔍 Scanning POST to: {url}")
                if result[0] == 1:
                    print("🚫 Intrusion Detected in POST!")
                    with open("intrusion_log.txt", "a") as f:
                        f.write(f"Blocked POST: {url}\n")
                    self.send_response(403)
                    self.end_headers()
                    self.wfile.write(b"403 Forbidden: Intrusion Detected (POST)")
                    return

                # Forward the POST request
                req = urllib.request.Request(url, data=post_data, method='POST')
                req.add_header("Content-Type", "application/x-www-form-urlencoded")
                with urllib.request.urlopen(req) as response:
                    content = response.read()
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(content)

            except Exception as e:
                print("❌ POST Proxy error:", e)
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"500 Internal Server Error")
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"404 Not Found")


def extract_features(query_string):
    length = len(query_string)
    digit_count = len(re.findall(r"\d", query_string))
    alpha_count = len(re.findall(r"[a-zA-Z]", query_string))
    special_count = len(re.findall(r"\W", query_string))
    sql_keywords = int(bool(re.search(r"(select|union|insert|drop|--|;)", query_string, re.IGNORECASE)))

    uppercase_count = len(re.findall(r"[A-Z]", query_string))
    lowercase_count = len(re.findall(r"[a-z]", query_string))
    space_count = len(re.findall(r"\s", query_string))

    # param_count: number of parameters in query if any
    param_count = 0
    if "?" in query_string:
        parsed_qs = parse_qs(urlparse(query_string).query)
        param_count = len(parsed_qs)

    digit_ratio = digit_count / length if length > 0 else 0
    alpha_ratio = alpha_count / length if length > 0 else 0
    special_ratio = special_count / length if length > 0 else 0

    return [
        length,
        digit_count,
        alpha_count,
        special_count,
        sql_keywords,
        uppercase_count,
        lowercase_count,
        space_count,
        param_count,
        digit_ratio,
        alpha_ratio,
        special_ratio
    ]

if __name__ == "__main__":
    with socketserver.TCPServer(("", PORT), ProxyHTTPRequestHandler) as httpd:
        print(f"🚀 Listening on http://127.0.0.1:{PORT}")
        httpd.serve_forever()
