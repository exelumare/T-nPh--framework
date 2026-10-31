"""Mock Server untuk testing TanPha Engine."""
from flask import Flask, request
import time

def create_app():
    app = Flask(__name__)

    @app.route("/")
    def index():
        return "Welcome to Mock Server"

    @app.route("/sqli-error")
    def sqli_error():
        q = request.args.get("q", "")
        q_clean = q.replace("/**/", " ").replace("/*!50000", "").replace("*/", "")
        
        if "'" not in q_clean and '"' not in q_clean and "\\" not in q_clean:
            return "OK: Normal page content here."
        if "AND '1'='1" in q_clean.upper():
            return "OK: Normal page content here."
        if "AND '1'='2" in q_clean.upper():
            return "No results found for your query."
        return f"SQL syntax error near '{q}'"

    @app.route("/sqli-time")
    def sqli_time():
        q = request.args.get("q", "")
        # Kalau ada SLEEP(5), kita beneran tidur 5 detik
        if "SLEEP(5)" in q.upper():
            time.sleep(5)
            return "OK: Normal page."
        return "OK: Normal page."

    @app.route("/footer-mysql")
    def footer_mysql():
        q = request.args.get("q", "")
        return f"<html><body>Search: {q}<footer>Powered by MySQL</footer></body></html>"

    return app
