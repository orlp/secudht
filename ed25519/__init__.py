import ctypes
import os

ed25519_dll = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "ed25519"))

c_create_seed = ed25519_dll.ed25519_create_seed
c_create_seed.argtypes = [ctypes.POINTER(ctypes.c_char)]

def create_seed():
    seed = ctypes.create_string_buffer(32)

    c_create_seed(seed)

    return seed.raw


c_create_keypair = ed25519_dll.ed25519_create_keypair
c_create_keypair.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]

def create_keypair(seed):
    public_key, private_key = ctypes.create_string_buffer(32), ctypes.create_string_buffer(64)

    c_create_keypair(public_key, private_key, seed)

    return public_key.raw, private_key.raw

c_sign = ed25519_dll.ed25519_sign
c_sign.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]


def sign(message, public_key, private_key):
    signature = ctypes.create_string_buffer(64)

    c_sign(signature, message, len(message), public_key, private_key)

    return signature.raw

c_verify = ed25519_dll.ed25519_verify
c_verify.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.c_size_t, ctypes.POINTER(ctypes.c_char)]


def verify(signature, message, public_key):
    return bool(c_verify(signature, message, len(message), public_key))


c_add_scalar = ed25519_dll.ed25519_add_scalar
c_add_scalar.argtypes = [ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char), ctypes.POINTER(ctypes.c_char)]


def add_scalar(scalar, public_key = None, private_key = None):
    if public_key is not None:
        public_key = ctypes.create_string_buffer(public_key)

    if private_key is not None:
        private_key = ctypes.create_string_buffer(private_key)

    c_add_scalar(public_key, private_key, scalar)

    if public_key and private_key:
        return public_key.raw, private_key.raw
    elif public_key:
        return public_key.raw
    elif private_key:
        return private_key.raw
