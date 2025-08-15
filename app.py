from flask import Flask, request, jsonify, render_template
import os
import base64
import secrets
import string
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__)

# === Helper: Derive AES key from ECC shared secret ===
def derive_aes_key(shared_secret):
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data'
    ).derive(shared_secret)

@app.route('/')
def index():
    return render_template('ency.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data.get('message', '').encode('utf-8')
    demo_mode = data.get('demoMode', True)

    # --- ECC Key Generation ---
    recipient_priv = ec.generate_private_key(ec.SECP256R1())
    recipient_pub = recipient_priv.public_key()

    eph_priv = ec.generate_private_key(ec.SECP256R1())
    eph_pub = eph_priv.public_key()

    eph_nums = eph_pub.public_numbers()

    # Smaller numbers in demo mode for visuals
    if demo_mode:
        ecc_x = eph_nums.x % 1000
        ecc_y = eph_nums.y % 1000
        pub_key_val = recipient_pub.public_numbers().x % 1000
        priv_key_val = recipient_priv.private_numbers().private_value % 1000
    else:
        ecc_x = eph_nums.x
        ecc_y = eph_nums.y
        pub_key_val = recipient_pub.public_numbers().x
        priv_key_val = recipient_priv.private_numbers().private_value

    # --- Shared Secret and AES Encryption ---
    shared_secret = eph_priv.exchange(ec.ECDH(), recipient_pub)
    aes_key = derive_aes_key(shared_secret)
    aesgcm = AESGCM(aes_key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, None)

    # --- Display Encrypted Message ---
    padding_length = secrets.randbelow(151)
    display_encrypted_message = ''.join(
        secrets.choice(string.ascii_letters + string.digits)
        for _ in range(padding_length)
    )

    return jsonify({
        "public_key": str(pub_key_val),
        "private_key": str(priv_key_val),
        "vector_encrypted": f"({ecc_x}, {ecc_y})",
        "display_encrypted": display_encrypted_message,
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "recipient_private_key": base64.b64encode(
            recipient_priv.private_numbers().private_value.to_bytes(32, 'big')
        ).decode(),
        "ephemeral_public_key_x": eph_nums.x,
        "ephemeral_public_key_y": eph_nums.y
    })

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    nonce = base64.b64decode(data['nonce'])
    ciphertext = base64.b64decode(data['ciphertext'])
    recipient_private_key_bytes = base64.b64decode(data['recipient_private_key'])
    recipient_private_value = int.from_bytes(recipient_private_key_bytes, 'big')

    recipient_priv = ec.derive_private_key(recipient_private_value, ec.SECP256R1())

    eph_x = data['ephemeral_public_key_x']
    eph_y = data['ephemeral_public_key_y']
    eph_pub = ec.EllipticCurvePublicNumbers(eph_x, eph_y, ec.SECP256R1()).public_key()

    shared_secret = recipient_priv.exchange(ec.ECDH(), eph_pub)
    aes_key = derive_aes_key(shared_secret)
    aesgcm = AESGCM(aes_key)
    decrypted_message = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')

    return jsonify({"decrypted_message": decrypted_message})

if __name__ == "__main__":
    app.run(debug=True)
