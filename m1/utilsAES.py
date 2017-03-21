from Crypto.Cipher import AES
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization
from Crypto.Util import Counter
from Crypto import Random
import string
import random



def encryptAES(key,
               input_text, iv):
    ctr = Counter.new(128)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr, IV=iv)
    missing = 0
    output_encrypted = ''
    while True:
        chunk = input_text[:aes.block_size]
        input_text = input_text[aes.block_size:]
        if len(chunk) == 0:
            break
        elif len(chunk) % aes.block_size != 0:
            missing = 16 - len(chunk)
            chunk += chr(missing) * (aes.block_size - len(chunk) % aes.block_size)
        output_encrypted += aes.encrypt(chunk)
    if missing == 0:
        chunk = chr(255) * aes.block_size
        output_encrypted += aes.encrypt(chunk)

    return output_encrypted


def decryptAES(key,
               encrypted_text, iv):
    ctr = Counter.new(128)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr, IV=iv)
    skip_list = [chr(x) for x in range(1, aes.block_size)]
    output_decrypted = ''
    copy_input = encrypted_text
    while True:
        chunk = copy_input[:aes.block_size]
        copy_input = copy_input[aes.block_size:]
        if len(chunk) == 0:
            break
        output_decrypted += aes.decrypt(chunk)

    last = output_decrypted[-aes.block_size:]
    if last != (chr(255) * aes.block_size):
        if last[len(last) - 1] in skip_list:
            idx = skip_list.index(last[len(last) - 1]) + 1
            last = last[:-idx]
        final = output_decrypted[:-aes.block_size] + last
    else:
        final = output_decrypted[:-aes.block_size]

    return final

def generateIV():
    rnd = Random.OSRNG.posix.new().read(AES.block_size)
    return rnd


def derivate(key, salt, spec):
    if spec == 'ECDHE-AES128-SHA':
        length = 16
    elif spec == 'ECDHE-AES256-SHA':
        length = 32
    hkdf = HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=b"hkdf-example", backend=default_backend())
    return hkdf.derive(key)


def serializePublicKey(key):
    return key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)


def loadPublicKey(key):
    return serialization.load_pem_public_key(key, backend=default_backend())


def generateHashMsg(key, msg):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(msg)
    return h.finalize()



def VerifyHashMsg(key, msg, hash_to_compare):
    h = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    h.update(msg)
    return h.verify(hash_to_compare)


def msggenerator(size=16, chars=string.ascii_uppercase + string.ascii_lowercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))
