# main.py

from flask import Flask, jsonify, request
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
import datetime

app = Flask(__name__)

# Generate RSA keys
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

# Define key ID and expiry
key_id = "example_key_id"
expiry_timestamp = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

# Convert keys to PEM format
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
).decode("utf-8")
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode("utf-8")

# Serve JWKS formatted keys
@app.route('/jwks')
def jwks():
    if datetime.datetime.utcnow() < expiry_timestamp:
        jwks_data = {
            "keys": [
                {
                    "kid": key_id,
                    "kty": "RSA",
                    "alg": "RS256",
                    "use": "sig",
                    "n": public_key.public_numbers().n,
                    "e": public_key.public_numbers().e
                }
            ]
        }
        return jsonify(jwks_data)
    else:
        return "Key has expired", 404

# Handle JWT issuance
@app.route('/auth', methods=['POST'])
def auth():
    expired = request.args.get('expired')
    if expired:
        key_to_use = private_key
        expiry_to_use = expiry_timestamp
    else:
        key_to_use = public_key
        expiry_to_use = datetime.datetime.utcnow() + datetime.timedelta(hours=1)

    payload = {'some': 'payload'}
    token = jwt.encode(payload, key_to_use, algorithm='RS256', 
headers={'kid': key_id, 'exp': expiry_to_use})
    return token

if __name__ == '__main__':
    app.run(port=8080)

