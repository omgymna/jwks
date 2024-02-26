# main.py

from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import datetime

app = Flask(__name__)

# Generate RSA key pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)

public_key = private_key.public_key()

private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode()

public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# Serve JWKS formatted keys

# Create a JWKS (JSON Web Key Set)
jwk = {
    "kid": "my-key-id",
    "alg": "RS256",
    "kty": "RSA",
    "use": "sig",
    "n": public_key.public_numbers().n,
    "e": public_key.public_numbers().e,
}
@app.route('/.well-known/jwks.json', methods=['GET'])
def jwks():
    return jsonify(keys=[jwk])

# Handle JWT issuance
@app.route('/auth', methods=['POST'])
def auth():
    username = request.json.get('username')
    password = request.json.get('password')
    
    # Check username and password (mock authentication)
    if username == "userABC" and password == "password123":
        # Generate a JWT with the current key
        now = datetime.datetime.utcnow()
        payload = {
            "sub": username,
            "iat": now,
            "exp": now + datetime.timedelta(minutes=15),
            "iss": "your-issuer",
            "aud": "your-audience",
            "kid": "my-key-id"
        }
        token = jwt.encode(payload, private_pem, algorithm='RS256')
        
        return jsonify(token=token.decode('utf-8'))
    
    return "Authentication failed", 401

if __name__ == '__main__':
    app.run(port=8080)

