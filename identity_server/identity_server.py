import ed25519
import time
import binascii
import hashlib
import struct

NODE_ID_SALT = hashlib.sha1("node_id_salt").digest()

sign_key = ed25519.keys.SigningKey("78ec3dda68d76ae686263085cfebdfe0a54786317b9cde9f7a7a4c48a0d54cf9", encoding="hex")
verify_key = sign_key.get_verifying_key()

users = {
    "nightcracker": (hashlib.sha1("test").digest(), None)
}


def generate_signature(username, password, pubkey):
    user = users.get(username, ("", None))

    if user[0] != hashlib.sha1(password).digest():
        return "invalid password"

    if user[1] is not None:
        return user[1]

    # TODO: randomly generate
    node_id = hashlib.sha1(username).digest()
    expiry_time = int(time.time() + 60 * 60 * 24 * 7)
    signature = sign_key.sign(node_id + struct.pack("<L", expiry_time) + pubkey)

    return (node_id, expiry_time, signature)


def verify_signature(node_id, expiry_time, pubkey, signature):
    try:
        verify_key.verify(signature, node_id + struct.pack("<L", expiry_time) + pubkey)
    except Exception:
        return False

    return True

pubkey = ed25519.create_keypair()[1].to_bytes()
node_id, expiry_time, signature = generate_signature("nightcracker", "test", pubkey)
print(verify_signature(node_id, expiry_time, pubkey, signature))
