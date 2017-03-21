# coding=utf8

import base64
import json
import os
import random
import string
import urllib2

from oscrypto import asymmetric

import OpenSSL.crypto as openssl
import PyKCS11
import asn1crypto
import oscrypto
from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.algorithms import AES
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from ocspbuilder import OCSPRequestBuilder
from oscrypto import asymmetric as oscrypto

from Crypto.Cipher import AES
import json
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives import serialization

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from Crypto.Util import Counter
from Crypto import Random
import PyKCS11
from pyasn1.codec.der import decoder as der_decoder
from pyasn1_modules import rfc2459
import time
import string

import base64
import random
import OpenSSL.crypto as openssl

from OpenSSL.crypto import X509StoreContextError

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from cryptography.exceptions import InvalidSignature
import cpuinfo
import platform
import netifaces

lib = '/usr/local/lib/libpteidpkcs11.so'


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


def loadCerts():
    store = openssl.X509Store()
    store.set_flags(openssl.X509StoreFlags.X509_STRICT | openssl.X509StoreFlags.POLICY_CHECK)
    for filename in os.listdir('CCCerts'):
        f = open('CCCerts/' + filename, 'rb')
        # conteudo
        fbytes = f.read()
        # fazer OCSP
        try:
            cert = openssl.load_certificate(openssl.FILETYPE_ASN1, fbytes)
        except:
            cert = openssl.load_certificate(openssl.FILETYPE_PEM, fbytes)
        store.add_cert(cert)
    return store

def verifyCert(certificate, store, server=False):
    if server == False:
        cert = oscrypto.load_certificate(openssl.dump_certificate(openssl.FILETYPE_ASN1, certificate))
        issuer_cert = oscrypto.load_certificate(getIssuer(certificate))
        ocsp_builder = OCSPRequestBuilder(cert, issuer_cert)

        ocsp_request = ocsp_builder.build().dump()

        CN = certificate.get_subject().commonName

        if CN in ('Baltimore CyberTrust Root', 'ECRaizEstado'):
            url = 'http://ocsp.omniroot.com/baltimoreroot/'
        elif CN[:-4] == 'Cartao de Cidadao':
            url = 'http://ocsp.ecee.gov.pt/'
        elif CN[:-5] == 'EC de Autenticacao do Cartao de Cidadao':
            url = 'http://ocsp.root.cartaodecidadao.pt/publico/ocsp'
        else:
            url = 'http://ocsp.auc.cartaodecidadao.pt/publico/ocsp'

        http_req = urllib2.Request(
            url,
            data=ocsp_request,
            headers={'Content-Type': 'application/ocsp-request'}
        )

        http = urllib2.urlopen(http_req)
        ocsp_response = http.read()

        ocsp_response = asn1crypto.ocsp.OCSPResponse.load(ocsp_response)
        response_data = ocsp_response.basic_ocsp_response['tbs_response_data']
        cert_response = response_data['responses'][0]

        if cert_response['cert_status'].name != 'good':
            return False

    try:
        certV = openssl.X509StoreContext(store, certificate)
        certV.verify_certificate()
    except:
        return False
    return True




def loadServerStore():
    store = openssl.X509Store()
    store.set_flags(openssl.X509StoreFlags.X509_STRICT | openssl.X509StoreFlags.POLICY_CHECK)
    with open('serverCerts/RootCert.crt', 'rb') as f:
        fbytes = f.read()
        cert = openssl.load_certificate(openssl.FILETYPE_PEM, fbytes)
        store.add_cert(cert)
    return store


def serverCert():
    cert = ""
    with open('serverCerts/ServerCert.cer', 'rb') as f:
        cert = f.read()
    return cert


def loadServerKey():
    key = ""
    with open("serverCerts/serverKey.pem", "rb") as f:
        fbytes = f.read()
        key = load_pem_private_key(fbytes, password=None, backend=default_backend())
    return key


def signClient(session, key, data):
    return ''.join(chr(i) for i in session.sign(key, data, mecha=PyKCS11.Mechanism(PyKCS11.CKM_SHA1_RSA_PKCS, "")))


def signServer(priv_k, data):
    return priv_k.sign(data, padding.PKCS1v15(), hashes.SHA1())


def verifySignedMsg(signed_msg, cert, data):
    try:
        certificado = x509.load_der_x509_certificate(cert, default_backend())
        certificado.public_key().verify(signed_msg, data, padding.PKCS1v15(), hashes.SHA1())
    except InvalidSignature:
        return False
    return True


def verificarAssinatura_Generic(request, certificado, campo):
    signed_msg = base64.b64decode(request[campo]['signed'])
    del request[campo]['signed']

    verify = verifySignedMsg(signed_msg, certificado, json.dumps(request, sort_keys=True))

    return verify


def verificarAssinatura_Random(request, certificado, campo, rand):
    signed_msg = base64.b64decode(request[campo]['signed'])

    verify = verifySignedMsg(signed_msg, certificado, rand)

    return verify


def getNBI(cert):
    cert = openssl.load_certificate(openssl.FILETYPE_ASN1, cert)
    return cert.get_subject().serialNumber


def getIssuer(cert):
    iss = cert.get_issuer()
    for filename in os.listdir('CCCerts'):
        f = open('CCCerts/' + filename, 'rb')
        fbytes = f.read()
        try:
            cert = openssl.load_certificate(openssl.FILETYPE_ASN1, fbytes)
        except:
            cert = openssl.load_certificate(openssl.FILETYPE_PEM, fbytes)

        if iss == cert.get_subject():
            return openssl.dump_certificate(openssl.FILETYPE_ASN1, cert)


def gerarHashMsg(msg):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(msg)
    return digest.finalize()


def verificarAck(request, certificado):
    signed_msg = base64.b64decode(request['signed'])
    del request['signed']
    verify = verifySignedMsg(signed_msg, certificado, json.dumps(request, sort_keys=True))
    return verify


def getHardwareClient():
    info = cpuinfo.get_cpu_info()
    del info['hz_actual_raw']
    del info['hz_advertised_raw']
    SO = platform.platform()
    lista = netifaces.interfaces()
    mac_addr = netifaces.ifaddresses(lista[1])[netifaces.AF_LINK]

    str_to_hash = str(info) + str(SO) + str(mac_addr)
    return gerarHashMsg(str_to_hash)


def getHardwareString():
    info = cpuinfo.get_cpu_info()
    str_info = ''
    str_info += 'Processador: ' + str(info['brand']) + ', Num. Cores: ' + str(info['count']) + ', Arch: ' + str(
        info['arch'])
    str_info += '\nSistema Operativo : ' + str(platform.platform())
    lista = netifaces.interfaces()
    mac_addr = netifaces.ifaddresses(lista[1])[netifaces.AF_LINK]
    str_info += '\nMac Address: ' + str(mac_addr)

    return str_info
