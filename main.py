import os
import hashlib
import functools
import ecdsa

from ecdsa.util import randrange
from ecdsa.ecdsa import curve_secp256k1
from ecdsa.curves import SECP256k1
from ecdsa import numbertheory

def ring_signature(siging_key, key_idx, M, y, G=SECP256k1.generator, hash_func=hashlib.sha3_256):
    """
        Generates a ring signature for a message given a specific set of
        public keys and a signing key belonging to one of the public keys
        in the set.
        @PARAMS
        ------
            signing_key: (int) The with which the message is to be anonymously signed.
            key_idx: (int) The index of the public key corresponding to the signature
                private key over the list of public keys that compromise the signature.
            M: (str) Message to be signed.
            y: (list) The list of public keys which over which the anonymous signature
                will be compose.
            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.
            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.
        RETURNS
        -------
            Signature (c_0, s, Y) :
                c_0: Initial value to reconstruct signature.
                s = vector of randomly generated values with encrypted secret to
                    reconstruct signature.
                Y = Link for current signer.
    """
    n = len(y)
    c = [0] * n
    s = [0] * n

    # STEP 1
    H = hash2(y, hash_func=hash_func)
    Y =  H * siging_key

    # STEP 2
    u = randrange(SECP256k1.order)
    c[(key_idx + 1) % n] = hash1([y, Y, M, G * u, H * u], hash_func=hash_func)

    # STEP 3
    for i in [ i for i in range(key_idx + 1, n) ] + [i for i in range(key_idx)]:

        s[i] = randrange(SECP256k1.order)

        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        c[(i + 1) % n] = hash1([y, Y, M, z_1, z_2], hash_func=hash_func)

    # STEP 4
    s[key_idx] = (u - siging_key * c[key_idx]) % SECP256k1.order
    return (c[0], s, Y)


def verify_ring_signature(message, y, c_0, s, Y, G=SECP256k1.generator, hash_func=hashlib.sha3_256):
    """
        Verifies if a valid signature was made by a key inside a set of keys.
        @PARAMS
        ------
            message: (str) message whos' signature is being verified.
            y: (list) set of public keys with which the message was signed.
            Signature:
                c_0: (int) initial value to reconstruct the ring.
                s: (list) vector of secrets used to create ring.
                Y = (int) Link of unique signer.
            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.
            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.
        @RETURNS
        -------
            Boolean value indicating if signature is valid.
    """
    n = len(y)
    c = [c_0] + [0] * (n - 1)

    H = hash2(y, hash_func=hash_func)

    for i in range(n):
        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        if i < n - 1:
            c[i + 1] = hash1([y, Y, message, z_1, z_2], hash_func=hash_func)
        else:
            return c_0 == hash1([y, Y, message, z_1, z_2], hash_func=hash_func)

    return False


def map_to_curve(x, P=curve_secp256k1.p()):
    """
        Maps an integer to an elliptic curve.
        @PARAMS
        ------
            x: (int) number to be mapped into E.
            P: (ecdsa.curves.curve_secp256k1.p) Modulo for elliptic curve.
        RETURNS
        -------
            (ecdsa.ellipticcurve.Point) Point in Curve
    """
    x -= 1
    y = 0
    found = False

    while not found:
        x += 1
        f_x = (x * x * x + 7) % P

        try:
            y = numbertheory.square_root_mod_prime(f_x, P)
            found = True
        except Exception as e:
            pass

    return ecdsa.ellipticcurve.Point(curve_secp256k1, x, y)


def hash1(msg, hash_func=hashlib.sha3_256):
    """
        Return an integer representation of the hash of a message. The
        message can be a list of messages that are concatenated with the
        concat() function.
        @PARAMS
        ------
            msg: (str or list) message(s) to be hashed.
            hash_func: (function) a hash function which can recieve an input
                string and return a hexadecimal digest.
        RETURNS
        -------
            Integer representation of hexadecimal digest from hash function.
    """
    return int('0x'+ hash_func(concat(msg)).hexdigest(), 16)


def hash2(msg, hash_func=hashlib.sha3_256):
    """
        Hashes a message into an elliptic curve point.
        @PARAMS
        ------
            msg: (str or list) message(s) to be hashed.
            hash_func: (function) Cryptographic hash function that recieves an input
                and outputs a digest.
        RETURNS
        -------
            ecdsa.ellipticcurve.Point to curve.
    """
    return map_to_curve(hash1(msg, hash_func=hash_func))


def concat(params):
    """
        Concatenates a list of parameters into a bytes. If one
        of the parameters is a list, calls itself recursively.
        @PARAMS
        ------
            @PARAMS: (list) list of elements, must be of type:
                - int
                - list
                - str
                - ecdsa.ellipticcurve.Point
        RETURNS
        -------
            concatenated bytes of all values.
    """
    n = len(params)
    bytes_value = [0] * n

    for i in range(n):

        if type(params[i]) is int:
            bytes_value[i] = params[i].to_bytes(32, 'big')
        if type(params[i]) is list:
            bytes_value[i] = concat(params[i])
        if type(params[i]) is ecdsa.ellipticcurve.Point:
            bytes_value[i] = params[i].x().to_bytes(32, 'big') + params[i].y().to_bytes(32, 'big')
        if type(params[i]) is str:
            bytes_value[i] = params[i].encode()

        if bytes_value[i] == 0:
            bytes_value[i] = params[i].x().to_bytes(32, 'big') + params[i].y().to_bytes(32, 'big')

    return functools.reduce(lambda x, y: x + y, bytes_value)


def stringify_point(p):
    """
        Represents an elliptic curve point as a string coordinate.
        @PARAMS
        ------
            p: ecdsa.ellipticcurve.Point - Point to represent as string.
        RETURNS
        -------
            (str) Representation of a point (x, y)
    """
    return '{},{}'.format(p.x(), p.y())


def main():
    number_participants = 10

    x = [ randrange(SECP256k1.order) for i in range(number_participants)]
    y = list(map(lambda xi: SECP256k1.generator * xi, x))
    w = [ randrange(SECP256k1.order) for i in range(number_participants)]

    message = "TEST MESSAGE, IT WILL RETURN TRUE"
    message2 = "TEST MESSAGE, IT WILL RETURN FALSE"
    print(y)

    i = 2
    signature = ring_signature(x[i], i, message, y)
    signature_2 = ring_signature(x[3], 3, message2, y)
    print(stringify_point(signature[2]))

    assert(verify_ring_signature(message, y, *signature))
    #print(signature)
    print(verify_ring_signature(message, y, *signature))
    print(verify_ring_signature(message, y, *signature_2))

if __name__ == '__main__':
    main()