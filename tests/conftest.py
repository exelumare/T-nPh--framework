"""Pytest configuration and fixtures."""
import pytest
import threading
import time
import sys
import os

# Pastikan root folder ada di sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from werkzeug.serving import make_server
from tests.mock_server import create_app

@pytest.fixture(scope="session")
def mock_server():
    app = create_app()
    server = make_server("127.0.0.1", 0, app) # Port 0 = random port
    port = server.server_port
    
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.5) # Tunggu server nyala
    
    yield f"http://127.0.0.1:{port}"
    
    server.shutdown()
    t.join()
