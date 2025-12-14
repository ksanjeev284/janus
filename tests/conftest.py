# tests/conftest.py
"""
Pytest fixtures for Janus test suite.
Provides Flask test client for bad_bank.py and shared utilities.
"""

import pytest
import sys
import os
import threading
import time
import socket

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from target_app.bad_bank import app as flask_app


def find_free_port():
    """Find an available port for testing."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        s.listen(1)
        port = s.getsockname()[1]
    return port


@pytest.fixture(scope="session")
def test_port():
    """Get a free port for the test server."""
    return find_free_port()


@pytest.fixture
def flask_client():
    """Create a Flask test client."""
    flask_app.config['TESTING'] = True
    with flask_app.test_client() as client:
        yield client


@pytest.fixture(scope="session")
def live_server(test_port):
    """
    Start a live Flask server for integration tests.
    Runs in a separate thread for the entire test session.
    """
    from werkzeug.serving import make_server
    
    flask_app.config['TESTING'] = True
    server = make_server('127.0.0.1', test_port, flask_app)
    thread = threading.Thread(target=server.serve_forever)
    thread.daemon = True
    thread.start()
    
    # Wait for server to be ready
    time.sleep(0.5)
    
    yield f"http://127.0.0.1:{test_port}"
    
    server.shutdown()


@pytest.fixture
def alice_token():
    """Return Alice's test token."""
    return "token_alice_123"


@pytest.fixture
def bob_token():
    """Return Bob's test token."""
    return "token_bob_456"


@pytest.fixture
def alice_jwt(flask_client):
    """Get a JWT for Alice from the login endpoint."""
    response = flask_client.post('/api/login', json={'username': 'alice'})
    data = response.get_json()
    return data.get('jwt_token')


# Data fixtures
@pytest.fixture
def sample_pii_response():
    """Sample response containing PII for testing."""
    return {
        "user_id": 10,
        "username": "testuser",
        "email": "test@example.com",
        "ssn": "123-45-6789",
        "phone": "555-123-4567",
        "credit_card": "4532015112830366",
        "api_key": "sk_live_abc123",
        "password_hash": "$2a$10$hash..."
    }


@pytest.fixture
def sample_jwt():
    """A sample JWT for testing."""
    return "eyJhbGciOiAiSFMyNTYiLCAidHlwIjogIkpXVCJ9.eyJ1c2VyX2lkIjogMTAsICJ1c2VybmFtZSI6ICJhbGljZSIsICJyb2xlIjogInVzZXIiLCAiZXhwIjogMTczNDE1OTMwOX0.h6oknxAvrRBjXv-gKSVKpt7epEQzOTR9"
