# target_app/bad_bank.py
"""
Vulnerable Bank API for testing Janus security scanner.
Contains intentional vulnerabilities: BOLA, Mass Assignment, and weak JWT.
"""

from flask import Flask, jsonify, request
import json
import base64
import hmac
import hashlib
from datetime import datetime
import uuid

app = Flask(__name__)

# --- DATABASE SIMULATION ---
# Two users with hardcoded tokens
USERS = {
    "token_alice_123": {"id": 10, "username": "alice", "balance": 5000, "role": "user", "is_admin": False},
    "token_bob_456":   {"id": 20, "username": "bob",   "balance": 150, "role": "user", "is_admin": False},
}

# In-memory user profiles (for Mass Assignment testing)
USER_PROFILES = {
    10: {"id": 10, "username": "alice", "email": "alice@bank.com", "role": "user", "is_admin": False, "plan": "basic"},
    20: {"id": 20, "username": "bob", "email": "bob@bank.com", "role": "user", "is_admin": False, "plan": "basic"},
}

# Orders/Transactions belonging to users
ORDERS = {
    555: {"owner_id": 10, "item": "MacBook Pro", "cost": 2500}, # Alice's Order
    999: {"owner_id": 20, "item": "Gaming Mouse", "cost": 50},  # Bob's Order
}

# JWT Configuration - DELIBERATELY WEAK for testing
JWT_SECRET = "secret"  # Weak secret!
JWT_ALGORITHM = "HS256"

# --- HELPERS ---
def get_user(req):
    token = req.headers.get("Authorization")
    # Support both simple tokens and Bearer tokens
    if token and token.startswith("Bearer "):
        token = token.replace("Bearer ", "")
    return USERS.get(token), token

def generate_jwt(payload, secret=JWT_SECRET):
    """Generate a simple JWT for testing."""
    header = {"alg": "HS256", "typ": "JWT"}
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    
    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
    signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
    
    return f"{message}.{signature_b64}"

def verify_jwt(token, secret=JWT_SECRET):
    """Verify a JWT - VULNERABLE: accepts alg:none!"""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            return None
        
        # Decode header
        header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
        header = json.loads(base64.urlsafe_b64decode(header_b64))
        
        # VULNERABILITY: Accept 'none' algorithm!
        if header.get('alg', '').lower() == 'none':
            payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
            return json.loads(base64.urlsafe_b64decode(payload_b64))
        
        # Verify signature
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)
        message = f"{parts[0]}.{parts[1]}"
        expected_sig = hmac.new(secret.encode(), message.encode(), hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).rstrip(b'=').decode()
        
        if parts[2] == expected_sig_b64:
            return json.loads(base64.urlsafe_b64decode(payload_b64))
        return None
    except Exception as e:
        print(f"JWT Error: {e}")
        return None

# --- ROUTES ---

@app.route('/api/login', methods=['POST'])
def login():
    """Login endpoint - returns both simple tokens and JWT."""
    data = request.get_json() or {}
    username = data.get('username', 'alice')
    
    user_id = 10 if username == 'alice' else 20
    jwt_token = generate_jwt({
        "sub": str(user_id),
        "username": username,
        "role": "user",
        "iat": int(datetime.now().timestamp())
    })
    
    return jsonify({
        "alice_token": "token_alice_123",
        "bob_token": "token_bob_456",
        "jwt_token": jwt_token,
        "message": "Use simple tokens for most tests, JWT for JWT attacks"
    })


# [VULNERABILITY 1]: IDOR / BOLA
# Alice (ID 10) can view Bob's Order (999) because we DON'T check ownership!
@app.route('/api/orders/<int:order_id>', methods=['GET'])
def get_order(order_id):
    user, _ = get_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    order = ORDERS.get(order_id)
    if not order:
        return jsonify({"error": "Order not found"}), 404

    # VULNERABLE CODE:
    # We return the order WITHOUT checking if user['id'] == order['owner_id']
    return jsonify({
        **order,
        "timestamp": datetime.now().isoformat(),  # Noisy field for Smart Diff testing
        "request_id": str(uuid.uuid4())  # Another noisy field
    })


# [SECURE ENDPOINT] (For comparison)
@app.route('/api/profile/<int:user_id>', methods=['GET'])
def get_profile(user_id):
    user, _ = get_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    # SECURE CODE:
    if user['id'] != user_id:
        return jsonify({"error": "Access Denied"}), 403
    
    profile = USER_PROFILES.get(user_id, {})
    return jsonify({
        **profile,
        "timestamp": datetime.now().isoformat()
    })


# [VULNERABILITY 2]: MASS ASSIGNMENT
# Accepts ANY fields in the update request!
@app.route('/api/profile/<int:user_id>', methods=['PUT', 'PATCH'])
def update_profile(user_id):
    user, _ = get_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    # Basic auth check
    if user['id'] != user_id:
        return jsonify({"error": "Access Denied"}), 403
    
    data = request.get_json() or {}
    
    # VULNERABLE CODE:
    # We blindly update ALL fields from user input!
    profile = USER_PROFILES.get(user_id, {})
    for key, value in data.items():
        profile[key] = value  # Mass Assignment vulnerability!
    
    USER_PROFILES[user_id] = profile
    
    return jsonify({
        "message": "Profile updated",
        "profile": profile
    })


# [VULNERABILITY 3]: WEAK JWT
# Protected endpoint that uses JWT auth
@app.route('/api/admin/dashboard', methods=['GET'])
def admin_dashboard():
    auth = request.headers.get("Authorization", "")
    
    if auth.startswith("Bearer "):
        token = auth.replace("Bearer ", "")
        payload = verify_jwt(token)
        
        if payload and payload.get('role') == 'admin':
            return jsonify({
                "message": "Welcome to admin dashboard!",
                "sensitive_data": {
                    "total_users": len(USERS),
                    "total_orders": len(ORDERS),
                    "revenue": 99999.99,
                    "secret_key": "super_secret_admin_key_12345"
                }
            })
        elif payload:
            return jsonify({"error": "Admin role required"}), 403
        else:
            return jsonify({"error": "Invalid JWT"}), 401
    else:
        return jsonify({"error": "Bearer token required"}), 401


# [VULNERABILITY 4]: Another BOLA for sensitive data
@app.route('/api/transactions/<int:user_id>', methods=['GET'])
def get_transactions(user_id):
    user, _ = get_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    # VULNERABLE: No ownership check!
    # Returning sensitive financial data
    fake_transactions = [
        {"id": 1, "amount": -50.00, "merchant": "Amazon", "date": "2024-01-15", "card_last4": "4532"},
        {"id": 2, "amount": -120.50, "merchant": "Uber", "date": "2024-01-14", "card_last4": "4532"},
        {"id": 3, "amount": 5000.00, "merchant": "Salary Deposit", "date": "2024-01-01", "ssn_last4": "1234"},
    ]
    
    return jsonify({
        "user_id": user_id,
        "email": f"user{user_id}@bank.com",  # Sensitive PII
        "phone": "555-123-4567",  # Sensitive PII
        "transactions": fake_transactions
    })


# ============================================================
# NEW VULNERABILITIES FOR PROFESSIONAL TESTING
# ============================================================

# [VULNERABILITY 5]: BFLA - Admin endpoints accessible by regular users
@app.route('/api/admin/users', methods=['GET'])
def admin_list_users():
    """BFLA VULNERABLE: No role check - any authenticated user can access."""
    user, _ = get_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    # VULNERABLE: No admin check!
    return jsonify({
        "users": [
            {"id": 10, "username": "alice", "email": "alice@bank.com", "role": "user", "password_hash": "$2b$12$LQv3c1yqBW..."},
            {"id": 20, "username": "bob", "email": "bob@bank.com", "role": "user", "password_hash": "$2b$12$NHG3v2xB..."},
            {"id": 1, "username": "admin", "email": "admin@bank.com", "role": "admin", "password_hash": "$2b$12$AdminHash..."},
        ],
        "total": 3,
        "api_key": "sk_live_PLACEHOLDER_1",  # PII Leak!
    })


@app.route('/api/admin/users/<int:user_id>/delete', methods=['DELETE'])
def admin_delete_user(user_id):
    """BFLA VULNERABLE: Any authenticated user can delete users!"""
    user, _ = get_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    # VULNERABLE: No admin check!
    return jsonify({"message": f"User {user_id} deleted", "success": True})


@app.route('/api/admin/config', methods=['GET'])
def admin_config():
    """BFLA VULNERABLE: Exposes system configuration."""
    user, _ = get_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    # VULNERABLE: Exposing secrets!
    return jsonify({
        "database_url": "postgresql://admin:SuperSecret123@db.internal:5432/bank",
        "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
        "aws_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "stripe_secret": "sk_live_PLACEHOLDER_FOR_DEMO",
        "jwt_secret": JWT_SECRET,
        "debug_mode": True
    })


@app.route('/api/admin/export', methods=['GET'])
def admin_export():
    """BFLA VULNERABLE: Data export accessible to all users."""
    user, _ = get_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    # VULNERABLE: Exposing all user data including sensitive PII
    return jsonify({
        "exported_at": datetime.now().isoformat(),
        "users": [
            {
                "id": 10, "username": "alice", "email": "alice@bank.com",
                "ssn": "123-45-6789", "credit_card": "4532015112830366",
                "dob": "1990-05-15", "address": "123 Main St, NYC"
            },
            {
                "id": 20, "username": "bob", "email": "bob@bank.com",
                "ssn": "987-65-4321", "credit_card": "5425233430109903",
                "dob": "1985-12-01", "address": "456 Oak Ave, LA"
            }
        ]
    })


# [VULNERABILITY 6]: Race Condition - Balance update without locking
# In-memory balance for race condition testing
RACE_BALANCE = {"user_10": 100.00}

@app.route('/api/wallet/balance', methods=['GET'])
def get_wallet_balance():
    """Get current wallet balance for race condition testing."""
    user, _ = get_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    balance_key = f"user_{user['id']}"
    return jsonify({
        "user_id": user['id'],
        "balance": RACE_BALANCE.get(balance_key, 100.00)
    })


@app.route('/api/wallet/withdraw', methods=['POST'])
def withdraw_money():
    """
    RACE CONDITION VULNERABLE: No locking on balance check/update!
    
    The vulnerability: We check the balance, then update it, without atomicity.
    Multiple simultaneous requests can all pass the balance check before any
    deduction is applied.
    """
    user, _ = get_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    data = request.get_json() or {}
    amount = float(data.get('amount', 10))
    
    balance_key = f"user_{user['id']}"
    current_balance = RACE_BALANCE.get(balance_key, 100.00)
    
    # VULNERABLE: Time gap between check and update!
    # No locking, no transaction, no atomicity
    import time
    time.sleep(0.01)  # Simulate database latency (makes race easier to exploit)
    
    if amount <= current_balance:
        # Deduct balance (vulnerable to race condition)
        RACE_BALANCE[balance_key] = current_balance - amount
        return jsonify({
            "success": True,
            "withdrawn": amount,
            "new_balance": RACE_BALANCE[balance_key],
            "transaction_id": str(uuid.uuid4())
        })
    else:
        return jsonify({"error": "Insufficient balance", "current": current_balance}), 400


@app.route('/api/wallet/reset', methods=['POST'])
def reset_wallet():
    """Reset wallet balance for testing."""
    user, _ = get_user(request)
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    
    balance_key = f"user_{user['id']}"
    RACE_BALANCE[balance_key] = 100.00
    return jsonify({"message": "Balance reset to 100.00", "balance": 100.00})


# [VULNERABILITY 7]: PII Leakage in various endpoints
@app.route('/api/debug/user/<int:user_id>', methods=['GET'])
def debug_user(user_id):
    """DEBUG endpoint that leaks everything (for PII scanner testing)."""
    return jsonify({
        "user_id": user_id,
        "username": f"user{user_id}",
        "email": f"user{user_id}@example.com",
        "phone": "555-123-4567",
        "ssn": "123-45-6789",
        "dob": "1990-01-01",
        "credit_card": "4532015112830366",
        "cvv": "123",
        "password_hash": "$2b$12$LQv3c1yqBWEHxnG7iLCxe.Zk5j4Q8mK1nOP2rS3t4UV5wX6yZ7A8b",
        "api_key": "sk_live_PLACEHOLDER_2",
        "aws_key": "AKIAIOSFODNN7EXAMPLE",
        "internal_notes": "Credit score: 750, Annual income: $85,000",
        "address": {
            "street": "123 Main Street",
            "city": "New York",
            "state": "NY",
            "zip": "10001"
        }
    })


# Health check
@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "ok", 
        "vulnerabilities": [
            "BOLA", "Mass Assignment", "Weak JWT", 
            "BFLA", "PII Leakage", "Race Condition"
        ]
    })


if __name__ == '__main__':
    print("""
    ╔═════════════════════════════════════════════════════════════════╗
    ║                     BAD BANK API v2.0                           ║
    ║            Intentionally Vulnerable for Testing                 ║
    ╠═════════════════════════════════════════════════════════════════╣
    ║  Vulnerabilities:                                                ║
    ║  1. BOLA: /api/orders/<id>, /api/transactions/<id>              ║
    ║  2. Mass Assignment: PUT /api/profile/<id>                      ║
    ║  3. Weak JWT: /api/admin/dashboard (secret='secret')            ║
    ║  4. BFLA: /api/admin/* (no role check!)                         ║
    ║  5. PII Leakage: /api/debug/user/<id>, /api/admin/export        ║
    ║  6. Race Condition: /api/wallet/withdraw                        ║
    ╚═════════════════════════════════════════════════════════════════╝
    """)
    app.run(port=5000, debug=True)

