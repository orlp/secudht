import ed25519
import binascii
import socket
import struct
import time
import hashlib


# opcodes
TIME_SYNC = chr(0)
CERT_REQUEST_INIT = chr(1)
CERT_REQUEST_CONFIRM = chr(2)
CERT_REQUEST_INVALID_AUTH = chr(3)


class CS(object):
    def __init__(self, port, keypair_seed):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socket.bind(("", port))
        self.socket.settimeout(0.05)

        self.public_key, self.private_key = ed25519.create_keypair(keypair_seed)

        self.certificate_requests = {}

        self.accounts = {
            "nightcracker": (0, binascii.unhexlify("f3b2ae5cb5032ae47c72de331d7dd674914716bd")),
            "orpheon": (1, binascii.unhexlify("fae11bb38d7fe48dced1a0c070d4c6efafeae931"))
        }


    def run(self):
        while True:
            self.expire_certificate_requests()

            try:
                data, address = self.socket.recvfrom(1024)
            except socket.error:
                continue

            self.handle_packet(data, address)


    def expire_certificate_requests(self):
        now = time.time()
        expired_requests = []

        for request, info in self.certificate_requests.items():
            if now > info[0]:
                expired_requests.append(request)

        for request in expired_requests:
            del self.certificate_requests[request]


    def handle_packet(self, data, address):
        if len(data) < 1:
            return

        opcode, data = data[0], data[1:]

        # time
        if opcode == TIME_SYNC:
            if len(data) != 32:
                print("TIME_SYNC packet received with incorrect size")
                return

            nonce = data
            timestamp = struct.pack("!Q", int(time.time() * 1000))

            message = timestamp
            message += ed25519.sign(nonce + timestamp, self.public_key, self.private_key)

            self.socket.sendto(TIME_SYNC + message, address)

        elif opcode == CERT_REQUEST_INIT:
            if len(data) != 96:
                print("CERT_REQUEST_INIT packet received with incorrect size")
                return
            
            nonce, username, proposed_pubkey = data[:32], data[32:64], data[64:96]
            username = struct.unpack("32p", username)[0]
            
            message = ed25519.sign(nonce + username + proposed_pubkey, self.public_key, self.private_key)

            self.socket.sendto(CERT_REQUEST_INIT + message, address)
            self.certificate_requests[nonce] = (time.time() + 10, username, proposed_pubkey)

        elif opcode == CERT_REQUEST_CONFIRM:
            if len(data) != (32 + 20 + 64):
                print("CERT_REQUEST_CONFIRM packet received with incorrect size")
                return

            nonce, auth, signature = data[:32], data[32:52], data[52:]

            if nonce not in self.certificate_requests:
                print("received CERT_REQUEST_CONFIRM with unknown nonce")
                return

            # we don't need to check the timeout - that's done elsewhere
            timeout, username, proposed_pubkey = self.certificate_requests[nonce]

            # only allow one response
            del self.certificate_requests[nonce]

            # invalid authentication
            if username not in self.accounts or hashlib.sha1(nonce + self.accounts[username][1]).digest() != auth:
                message = nonce
                message += ed25519.sign(nonce, self.public_key, self.private_key)

                self.socket.sendto(CERT_REQUEST_INVALID_AUTH + message, address)

                return

            if not ed25519.verify(signature, nonce + auth, proposed_pubkey):
                print("received CERT_REQUEST_CONFIRM with invalid signature")
                return

            scalar = ed25519.create_seed()
            pubkey = ed25519.add_scalar(scalar, proposed_pubkey)
            userid = struct.pack(">L", self.accounts[username][0])
            expiry = struct.pack(">H", round((time.time() / (60 * 60 * 24 * 7)) + 1)) # one week

            message = scalar
            message += userid
            message += expiry
            message += ed25519.sign(pubkey + userid + expiry, self.public_key, self.private_key)

            self.socket.sendto(CERT_REQUEST_CONFIRM + message, address)
            

certification_service = CS(2350, binascii.unhexlify("78ec3dda68d76ae686263085cfebdfe0a54786317b9cde9f7a7a4c48a0d54cf9"))
certification_service.run()
