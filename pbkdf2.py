import hmac
import hashlib
import operator
import itertools
import struct

_pack_int = struct.Struct('>I').pack

def pbkdf2(data, salt, iterations=1000, keylen=20, hashfunc=None):
    hashfunc = hashfunc or hashlib.sha1
    mac = hmac.new(data, None, hashfunc)

    def _pseudorandom(x, mac=mac):
        h = mac.copy()
        h.update(x)
        return map(ord, h.digest())

    buf = []
    for block in range(1, -(-keylen // mac.digest_size) + 1):
        rv = u = _pseudorandom(salt + _pack_int(block))
        
        for i in range(iterations - 1):
            u = _pseudorandom("".join(map(chr, u)))
            rv = itertools.starmap(operator.xor, itertools.izip(rv, u))

        buf.extend(rv)

    return "".join(map(chr, buf))[:keylen]
