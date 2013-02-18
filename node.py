import socket
import os
import time
import sys
import struct
import ed25519
import binascii
import hashlib
import pbkdf2


# opcodes
TIME_SYNC = chr(0)
CERT_REQUEST_INIT = chr(1)
CERT_REQUEST_CONFIRM = chr(2) 
CERT_REQUEST_INVALID_AUTH = chr(3)


class Node(object):
    def __init__(self, ca_address, ca_public_key, username, password):
        # socket
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self.socket.settimeout(0.05)

        self.password_key = pbkdf2.pbkdf2(password, hashlib.sha1(username).digest())

        # network time
        self.network_time_offset = None
        self.last_network_time_request_time = 0
        self.last_network_time_request_nonce = ""

        # certificate
        self.ca_address = ca_address
        self.ca_public_key = ca_public_key

        self.username = username
        self.user_id = 0
        self.public_key = ""
        self.private_key = ""
        self.certificate = None

        self.last_certificate_request_time = 0
        self.last_certificate_request_public_key = ""
        self.last_certificate_request_private_key = ""
        self.last_certificate_request_nonce = ""


    def run(self):
        while True:
            self.manage_network_time()
            self.manage_certificate()

            try:
                data, address = self.socket.recvfrom(1024)
            except socket.error:
                pass
            else:
                self.handle_packet(data, address)


    def get_network_time(self):
        if self.network_time_offset is None:
            return 0

        else:
            return time.time() + self.network_time_offset


    def handle_packet(self, data, address):
        if len(data) < 1:
                return

        opcode, data = data[0], data[1:]

        # time sync
        if opcode == TIME_SYNC:
            if len(data) != (8 + 64):
                print("TIME_SYNC packet received with incorrect size")
                return

            timestamp, signature = data[:8], data[8:]
            
            # make sure the time is actually from the CA AND contains the correct nonce
            # this implicitly rejects too old responses, because the nonce would have changed already
            if not ed25519.verify(signature, self.last_network_time_request_nonce + timestamp, self.ca_public_key):
                return

            now = time.time()
            latency_correction = (now - self.last_network_time_request_time) / 2

            self.network_time_offset = struct.unpack("!Q", timestamp)[0] / 1000. - latency_correction - now 

        # certificate request reply from the CA 
        elif opcode == CERT_REQUEST_INIT:
            if len(data) != 64:
                print("CERT_REQUEST_INIT packet received with incorrect size")
                return

            check_message = self.last_certificate_request_nonce + self.username + self.last_certificate_request_public_key
            signature = data

            if not ed25519.verify(signature, check_message, self.ca_public_key):
                print("Got wrong CERT_REQUEST_INIT signature")
                return

            message = self.last_certificate_request_nonce
            message += hashlib.sha1(self.last_certificate_request_nonce + self.password_key).digest() 
            message += ed25519.sign(message, self.last_certificate_request_public_key, self.last_certificate_request_private_key)

            self.socket.sendto(CERT_REQUEST_CONFIRM + message, address)

        elif opcode == CERT_REQUEST_CONFIRM:
            if len(data) != (32 + 4 + 2 + 64):
                print("Got wrong CERT_REQUEST_CONFIRM signature")
                return

            scalar, user_id, expiry, certificate = data[:32], data[32:36], data[36:38], data[38:]

            
            public_key, private_key = ed25519.add_scalar(scalar, self.last_certificate_request_public_key, self.last_certificate_request_private_key)

            if ed25519.verify(certificate, public_key + user_id + expiry, self.ca_public_key):
                self.public_key = public_key
                self.private_key = private_key
                self.certificate = certificate
                self.user_id = struct.unpack(">L", user_id)[0]
                expiry = struct.unpack("@H", expiry)[0]

                print("\nIdentification successful")
                print("-------------------------")
                print("User ID: {}".format(self.user_id))
                print("Public key: " + binascii.hexlify(self.public_key))
                print("Certificate: " + binascii.hexlify(self.certificate))


        elif opcode == CERT_REQUEST_INVALID_AUTH:
            nonce, signature = data[:32], data[32:]
            
            # correct signature?
            if not ed25519.verify(signature, nonce, self.ca_public_key):
                return

            # our nonce?
            if nonce != self.last_certificate_request_nonce:
                return

            print("Invalid username or password.")
            sys.exit(0)
            

    def manage_network_time(self):
        if self.network_time_offset is None and (time.time() - self.last_network_time_request_time) > 2.5:
            self.last_network_time_request_time = time.time()
            self.last_network_time_request_nonce = os.urandom(32)

            self.socket.sendto(TIME_SYNC + self.last_network_time_request_nonce, self.ca_address)


    def manage_certificate(self):
        if self.certificate is None and (time.time() - self.last_certificate_request_time) > 5.0:
            self.last_certificate_request_time = time.time()
            self.last_certificate_request_nonce = os.urandom(32)
            self.last_certificate_request_public_key, self.last_certificate_request_private_key = ed25519.create_keypair(ed25519.create_seed())
            
            message = self.last_certificate_request_nonce
            message += struct.pack("32p", self.username)
            message += self.last_certificate_request_public_key 

            self.socket.sendto(CERT_REQUEST_INIT + message, self.ca_address)


username = raw_input("Enter your username: ").strip()
password = raw_input("Enter your password: ").strip()

node = Node(("127.0.0.1", 2350), binascii.unhexlify("b75818634da1c2e6627efbd2179af3fbd980fdbd06fb3d1ab9b2ae9550f801d1"), username, password)
node.run()
