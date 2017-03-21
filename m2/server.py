# encoding: utf-8
#
# jpbarraca@ua.pt
# jmr@ua.pt 2016

# vim setings:
# :set expandtab ts=4
import base64
import json
import logging
import os
import sys
import time
from select import *
from socket import *
import random
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec

import utilsAES

import OpenSSL.crypto as openssl

# Server address
HOST = '0.0.0.0'  # All available interfaces
PORT = 8080  # The server port

BUFSIZE = 1024 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 128 * 1024

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2

C1 = 'ECDHE-AES128-SHA'
C2 = 'ECDHE-AES256-SHA'
CIPHERS = [C2, C1]


class Client:
    count = 0

    def __init__(self, socket, addr):
        self.socket = socket
        self.bufin = ""
        self.bufout = ""
        self.addr = addr
        self.id = None
        self.sa_data = {}
        self.sa_data['ids'] = {}
        self.level = random.randint(0, 3)
        self.state = STATE_NONE
        self.name = "Unknown"
        self.cert = ""
        self.bi_number = None
        self.random_enviado = 0
        self.acks_dict = {}

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(id=%r addr:%s name:%s level:%d state:%d)" % (
            self.id, str(self.addr), self.name, self.level, self.state)

    def asDict(self):
        return {'id': self.id, 'level': self.level, 'name': self.name}

    def setState(self, state):
        if state not in [STATE_CONNECTED, STATE_NONE, STATE_DISCONNECTED]:
            return

        self.state = state

    def parseReqs(self, data):
        """Parse a chunk of data from this client.
        Return any complete requests in a list.
        Leave incomplete requests in the buffer.
        This is called whenever data is available from client socket."""

        if len(self.bufin) + len(data) > MAX_BUFSIZE:
            logging.error("Client (%s) buffer exceeds MAX BUFSIZE. %d > %d",
                          (self, len(self.bufin) + len(data), MAX_BUFSIZE))
            self.bufin = ""

        self.bufin += data
        reqs = self.bufin.split(TERMINATOR)
        self.bufin = reqs[-1]
        return reqs[:-1]

    def send(self, obj):
        """Send an object to this client.
        """
        try:
            self.bufout += json.dumps(obj) + "\n\n"
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)", self)

    def close(self):
        """Shuts down and closes this client's socket.
        Will log error if called on a client with closed socket.
        Never fails.
        """
        logging.info("Client.close(%s)", self)
        try:
            # Shutdown will fail on a closed socket...
            self.socket.close()
        except:
            logging.exception("Client.close(%s)", self)

        logging.info("Client Closed")


class ChatError(Exception):
    """This exception should signal a protocol error in a client request.
    It is not a server error!
    It just means the server must report it to the sender.
    It should be dealt with inside handleRequest.
    (It should allow leaner error handling code.)
    """
    pass


def ERROR(msg):
    """Raise a Chat protocol error."""
    raise ChatError(msg)


class Server:
    def __init__(self, host, port):
        self.ss = socket(AF_INET, SOCK_STREAM)  # the server socket (IP \ TCP)
        self.ss.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        self.ss.bind((host, port))
        self.ss.listen(10)
        logging.info("Secure IM server listening on %s", self.ss.getsockname())
        # clients to manage (indexed by socket and by name):
        self.clients = {}  # clients (key is socket)
        self.id2client = {}  # clients (key is id)
        self.to_delete = {}
        self.store = utilsAES.loadCerts()
        self.priv_k = utilsAES.loadServerKey()
        self.certificate = utilsAES.serverCert()
        self.dict_certs = {}
        self.lapadula = {}

    def stop(self):
        """ Stops the server closing all sockets
        """
        logging.info("Stopping Server")
        try:
            self.ss.close()
        except:
            logging.exception("Server.stop")

        for csock in self.clients:
            try:
                self.clients[csock].close()  # Client.close!
            except:
                # this should not happen since close is protected...
                logging.exception("clients[csock].close")

        # If we delClient instead, the following would be unnecessary...
        self.clients.clear()
        self.id2client.clear()

    def addClient(self, csock, addr):
        """Add a client connecting in csock."""
        if csock in self.clients:
            logging.error("Client NOT Added: %s already exists", self.clients[csock])
            return

        client = Client(csock, addr)
        self.clients[client.socket] = client
        logging.info("Client added: %s", client)

    def delClient(self, csock):
        """Delete a client connected in csock."""
        if csock not in self.clients:
            logging.error("Client NOT deleted: %s not found", self.clients[csock])
            return

        client = self.clients[csock]
        assert client.socket == csock, "client.socket (%s) should match key (%s)" % (client.socket, csock)
        if client.id in self.id2client.keys():
            del self.id2client[client.id]
            #del self.dict_certs[client.id]
        del self.clients[client.socket]
        client.close()
        logging.info("Client deleted: %s", client)

    def accept(self):
        """Accept a new connection.
        """
        try:
            csock, addr = self.ss.accept()
            self.addClient(csock, addr)
        except:
            logging.exception("Could not accept client")

    def flushin(self, s):
        """Read a chunk of data from this client.
        Enqueue any complete requests.
        Leave incomplete requests in buffer.
        This is called whenever data is available from client socket.
        """
        client = self.clients[s]
        data = None
        try:
            data = s.recv(BUFSIZE)
            logging.info("Received data from %s. Message:\n%r", client, data)
        except:
            logging.exception("flushin: recv(%s)", client)
            logging.error("Received invalid data from %s. Closing", client)
            self.delClient(s)
        else:
            if len(data) > 0:
                reqs = client.parseReqs(data)
                for req in reqs:
                    self.handleRequest(s, req)
            else:
                self.delClient(s)

    def flushout(self, s):
        """Write a chunk of data to client.
        This is called whenever client socket is ready to transmit data.

        Quando a mensagem foi enviada, e se estiverem alguns clientes para serem apagados, a eliminação de toda a
        informação do cliente é efetuada
        """
        if s not in self.clients:
            # this could happen before, because a flushin might have deleted the client
            logging.error("BUG: Flushing out socket that is not on client list! Socket=%s", str(s))
            return

        client = self.clients[s]
        try:
            sent = client.socket.send(client.bufout[:BUFSIZE])
            logging.info("Sent %d bytes to %s. Message:\n%r", sent, client, client.bufout[:sent])
            client.bufout = client.bufout[sent:]  # leave remaining to be sent later
            if len(self.to_delete.keys()) > 0:
                for k in self.to_delete.keys():
                    self.delClient(k)
                self.to_delete = {}

        except:
            logging.exception("flushout: send(%s)", client)
            # logging.error("Cannot write to client %s. Closing", client)
            self.delClient(client.socket)

    def loop(self):
        while True:
            # sockets to select for reading: (the server socket + every open client connection)
            rlist = [self.ss] + self.clients.keys()
            # sockets to select for writing: (those that have something in bufout)
            wlist = [sock for sock in self.clients if len(self.clients[sock].bufout) > 0]
            #logging.debug("select waiting for %dR %dW %dX", len(rlist), len(wlist), len(rlist))
            (rl, wl, xl) = select(rlist, wlist, rlist)
            #logging.debug("select: %s %s %s", rl, wl, xl)

            # Deal with incoming data:
            for s in rl:
                if s is self.ss:
                    self.accept()
                elif s in self.clients:
                    self.flushin(s)
                else:
                    logging.error("Incoming, but %s not in clients anymore", s)

            # Deal with outgoing data:
            for s in wl:
                if s in self.clients:
                    self.flushout(s)
                else:
                    logging.error("Outgoing, but %s not in clients anymore", s)

            for s in xl:
                logging.error("EXCEPTION in %s. Closing", s)
                self.delClient(s)

    def handleRequest(self, s, request):
        """Handle a request from a client socket.
        """
        client = self.clients[s]
        try:
            logging.info("HANDLING message from %s: %r", client, repr(request))

            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return

            if 'type' not in req:
                return

            if req['type'] == 'ack':
                try:
                    if 'signed' in req.keys():
                        if utilsAES.verificarAck(req, client.cert):
                            del client.acks_dict[base64.b64decode(req['hash'])]
                            return
                        else:
                            logging.error("Assinatura de ACK recebido inválida!")
                            client.close()
                    else:
                        del client.acks_dict[base64.b64decode(req['hash'])]
                        return
                except:
                    logging.error("Hash invalido")
                    client.close()
                    return


            if req['type'] == 'connect':
                self.processConnect(client, req)
                # client.send({'type': 'ack'})
            elif req['type'] == 'secure':
                elapsed_time = time.time() - client.sa_data['start_time']
                if elapsed_time >= 600:
                    self.regenerateSecret(client)
                self.processSecure(client, req)
                # client.send({'type': 'ack'})

        except Exception, e:
            logging.exception("Could not handle request")

    def clientList(self):
        """
        Return the client list
        """
        cl = []
        for k in self.clients:
            cl.append(self.clients[k].asDict())
        return cl

    def processConnect(self, sender, request):
        '''
        Nesta função processamos as fases de conexão entre o cliente e o Servidor.
        OU A geração de novos segredos entre cliente e servidor

        Quando é recebida a fase 1 do cliente:
            O servidor recebe o/os cipherspecs que o cliente quer utilizar. Se enviar os 2 suportados, é escolhido o mais seguro, se não o que é enviado.

        Qaudno é recebida a fase 3 do cliente:
            É guardada a chave publica do cliente, gera-se o segredo partilhado e é enviada a chave publica do servidor com aquele cliente, para o cliente.

        Quando é recebida a fase 5 do cliente:
            Os hashes sao verificados e a mensagem é decifrada.
            é cifrada uma mensagem para o cliente e é gerado um hamc, todos os parametros são enviados, para ele tentar decifrar a mensagem e verificar o hmac.

        Quando é recebida a fase 7 do client:
            É mais uma vez feita a decifra e verificação de uma mensagem, o cliente envia o seu ID, se ele for inválido (já existir no servidor) o servidor gera um ID e envia ao cliente.
            No fim desta fase, o estado do cliente é alterado para CONECTADO e é iniciado o temporizador de expiração de chave geral de sessão entre cliente e servidor
            E também é iniciado o contador ede mensagens até ser atingida a expiração de chave geral de sessão

        As fases recebidas [2,4] correspondem á regeneração de um segredo, ficando ele novamente gerado na receçao da fase 4.

        :param sender:
        :param request:
        :return:
        '''
        """
        Process a connect message from a client
        """
        if sender.state == STATE_CONNECTED:
            logging.warning("Client is already connected: %s" % sender)
            return

        if not all(k in request.keys() for k in ("name", "ciphers", "phase", "id")):
            logging.warning("Connect message with missing fields")
            return

        if request['phase'] == 1:

            hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
            sender.send({'type':'ack', 'hash':hash_to_send})


            # REPETICOES
            if len(self.dict_certs.keys()) > 0:
                for k,v in self.dict_certs.iteritems():
                    if v == base64.b64decode(request['data']['certificate']):
                        logging.error("Certificado Repetido!")
                        self.delClient(sender.socket)
                        sender.close()
                        return

            sender.cert = base64.b64decode(request['data']['certificate'])
            certificado = openssl.load_certificate(openssl.FILETYPE_ASN1, sender.cert)

            if utilsAES.verifyCert(certificado, self.store) == False:
                logging.error("Certificado Inválido!")
                self.delClient(sender.socket)
                sender.close()
                return

            merged_specs = [x for x in request['ciphers'] if x in CIPHERS]
            if len(merged_specs) == 0:
                msg = {'type': 'connect', 'phase': request['phase'] + 1, 'name': request['name'],
                       'ciphers': [],
                       'data': {}}
                sender.send(msg)
                return

            sender.random_enviado = os.urandom(16)
            msg = {'type': 'connect', 'phase': request['phase'] + 1, 'name': request['name'], 'ciphers': merged_specs,
                   'data': {'certificate': base64.b64encode(self.certificate), 'random': base64.b64encode(sender.random_enviado)}}

            sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

            sender.sa_data['suportados'] = merged_specs
            sender.sa_data['ids'][request['id']] = request

            sender.send(msg)
            return

        # generate new secret
        if request['phase'] == 2:

            hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
            sender.send({'type':'ack', 'hash':hash_to_send})

            sender.cert = base64.b64decode(request['data']['certificate'])
            certificado = openssl.load_certificate(openssl.FILETYPE_ASN1, sender.cert)



            if utilsAES.verifyCert(certificado, self.store) == False:
                logging.error("Certificado Inválido!")
                self.delClient(sender.socket)
                sender.close()
                return

            # REPETICOES
            if len(self.dict_certs.keys()) > 0:
                for k,v in self.dict_certs.iteritems():
                    if v == base64.b64decode(request['data']['certificate']):
                        logging.error("Certificado Repetido!")
                        self.delClient(sender.socket)
                        sender.close()
                        return


            sender.random_enviado = os.urandom(16)
            signed = utilsAES.signServer(self.priv_k, base64.b64decode(request['data']['random']))
            msg = {'type': 'connect', 'phase': request['phase'] + 1, 'name': request['name'],
                   'ciphers': [sender.sa_data['cipherspec']],
                   'data': {'random': base64.b64encode(sender.random_enviado), 'signed':base64.b64encode(signed)}}

            sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

            logging.info("Connect continue to phase " + str(msg['phase']))
            sender.send(msg)
            return

        if request['phase'] == 3:
            hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
            sender.send({'type':'ack', 'hash':hash_to_send})

            if utilsAES.verificarAssinatura_Random(request, sender.cert, 'data', sender.random_enviado) == False:
                logging.error("Assinatura de Random Inválida! Abortar ligação com o Cliente")
                self.delClient(sender.socket)
                sender.close()
                return

            client_rand = base64.b64decode(request['data']['random'])


            sender.sa_data['ids'][request['id']] = request
            sender.sa_data['cipherspec'] = request['ciphers']

            msg = {'type': 'connect', 'phase': request['phase'] + 1, 'name': request['name'],
                   'ciphers': [sender.sa_data['cipherspec']],
                   'data': {'signed':base64.b64encode(utilsAES.signServer(self.priv_k, client_rand))}}

            sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

            logging.info("Connect continue to phase " + str(msg['phase']))
            sender.send(msg)
            return

        # generate new secret
        if request['phase'] == 4:

            hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
            sender.send({'type':'ack', 'hash':hash_to_send})

            if utilsAES.verificarAssinatura_Random(request, sender.cert, 'data', sender.random_enviado) == False:
                logging.error("Assinatura de Random Inválida! Abortar ligação com o Cliente")
                self.delClient(sender.socket)
                sender.close()
                return

            sender.sa_data['my_privk'] = ec.generate_private_key(ec.SECP384R1(), default_backend())
            sender.sa_data['my_pubk'] = sender.sa_data['my_privk'].public_key()
            msg = {'type': 'connect', 'phase': request['phase'] + 1, 'name': sender.name,
                   'ciphers': [sender.sa_data['cipherspec']],
                   'data': {'pub': utilsAES.serializePublicKey(sender.sa_data['my_pubk'])}}

            signed = utilsAES.signServer(self.priv_k, json.dumps(msg, sort_keys=True))

            msg['data']['signed'] = base64.b64encode(signed)

            sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

            sender.send(msg)
            return

        if request['phase'] == 5:

            hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
            ack = {'type': 'ack', 'hash': hash_to_send}
            signed = utilsAES.signServer(self.priv_k, json.dumps(ack, sort_keys=True))
            ack['signed'] = base64.b64encode(signed)
            sender.send(ack)

            if utilsAES.verificarAssinatura_Generic(request, sender.cert, 'data') == False:
                logging.error("Assinatura de Mensagem Inválida!")
                self.delClient(sender.socket)
                sender.close()
                return


            sender.sa_data['client_pub_key'] = utilsAES.loadPublicKey(str(request['data']['pub']))
            sender.sa_data['my_priv_key'] = ec.generate_private_key(ec.SECP384R1(), default_backend())
            sender.sa_data['my_pub_key'] = sender.sa_data['my_priv_key'].public_key()
            sender.sa_data['segredo'] = self.generateSecret(sender.sa_data['my_priv_key'],sender.sa_data['client_pub_key'])



            msg = {'type': 'connect', 'phase': request['phase'] + 1, 'name': request['name'],
                   'ciphers': [sender.sa_data['cipherspec']],
                   'data': {'pub': utilsAES.serializePublicKey(sender.sa_data['my_pub_key'])}}

            signed = utilsAES.signServer(self.priv_k, json.dumps(msg, sort_keys=True))

            msg['data']['signed'] = base64.b64encode(signed)

            sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

            sender.send(msg)
            return

        #generate new secret
        if request['phase'] == 6:

            hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
            ack = {'type': 'ack', 'hash': hash_to_send}
            signed = utilsAES.signServer(self.priv_k, json.dumps(ack, sort_keys=True))
            ack['signed'] = base64.b64encode(signed)
            sender.send(ack)

            if utilsAES.verificarAssinatura_Generic(request, sender.cert, 'data') == False:
                logging.error("Assinatura de Mensagem Inválida!")
                self.delClient(sender.socket)
                sender.close()
                return

            sender.sa_data['client_pub_key'] = utilsAES.loadPublicKey(str(request['data']['pub']))
            sender.sa_data['segredo'] = self.generateSecret(sender.sa_data['my_privk'],
                                                            sender.sa_data['client_pub_key'])

            salt_cifra, salt_hmac, iv, msg_cifrada = self.cipherMessage(sender.sa_data['segredo'],
                                                                        'tudo o que mando vai',
                                                                        sender.sa_data['cipherspec'])

            msg = {'type': 'connect', 'phase': request['phase'] + 1, 'name': request['name'],
                   'ciphers': [sender.sa_data['cipherspec']],
                   'data': {'cif': base64.b64encode(msg_cifrada),
                            'IV': iv,
                            'salt-cifra': base64.b64encode(salt_cifra),
                            'salt-hash': base64.b64encode(salt_hmac)}}

            signed = utilsAES.signServer(self.priv_k, json.dumps(msg, sort_keys=True))

            msg['data']['signed'] = base64.b64encode(signed)

            sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

            sender.send(msg)
            return

        if request['phase'] == 7:

            hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
            ack = {'type': 'ack', 'hash': hash_to_send}
            signed = utilsAES.signServer(self.priv_k, json.dumps(ack, sort_keys=True))
            ack['signed'] = base64.b64encode(signed)
            sender.send(ack)

            if utilsAES.verificarAssinatura_Generic(request, sender.cert, 'data') == False:
                logging.error("Assinatura de Mensagem Inválida!")
                self.delClient(sender.socket)
                sender.close()
                return

            recebido = request['data']
            msg_decifrada = self.decipherMessage(base64.b64decode(recebido['salt-cifra']),
                                                 base64.b64decode(recebido['salt-hash']),
                                                 recebido['IV'],
                                                 sender.sa_data['segredo'],
                                                 base64.b64decode(recebido['cif']),
                                                 sender.sa_data['cipherspec'],
                                                 sender)

            salt_cifra, salt_hmac, iv, msg_cifrada = self.cipherMessage(sender.sa_data['segredo'],
                                                                        'Tudo o que eu mando vai encriptado',
                                                                        sender.sa_data['cipherspec'])

            msg = {'type': 'connect', 'phase': request['phase'] + 1, 'name': request['name'],
                   'ciphers': [sender.sa_data['cipherspec']],
                   'data': {'cif': base64.b64encode(msg_cifrada),
                            'IV': iv,
                            'salt-cifra': base64.b64encode(salt_cifra),
                            'salt-hash': base64.b64encode(salt_hmac)}}

            signed = utilsAES.signServer(self.priv_k, json.dumps(msg, sort_keys=True))

            msg['data']['signed'] = base64.b64encode(signed)

            sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

            sender.send(msg)
            return

        # generate new secret
        if request['phase'] == 8:

            hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
            ack = {'type': 'ack', 'hash': hash_to_send}
            signed = utilsAES.signServer(self.priv_k, json.dumps(ack, sort_keys=True))
            ack['signed'] = base64.b64encode(signed)
            sender.send(ack)

            if utilsAES.verificarAssinatura_Generic(request, sender.cert, 'data') == False:
                logging.error("Assinatura de Mensagem Inválida!")
                self.delClient(sender.socket)
                sender.close()
                return

            recebido = request['data']
            msg_decifrada = self.decipherMessage(base64.b64decode(recebido['salt-cifra']),
                                                 base64.b64decode(recebido['salt-hash']),
                                                 recebido['IV'], sender.sa_data['segredo'],
                                                 base64.b64decode(recebido['cif']),
                                                 sender.sa_data['cipherspec'],
                                                 sender)

            sender.level = random.randint(0,3)

            salt_cifra, salt_hmac, iv, msg_cifrada = self.cipherMessage(sender.sa_data['segredo'],
                                                                        json.dumps(
                                                                            {'status': 'OK', 'level': sender.level}),
                                                                        sender.sa_data['cipherspec'])

            msg = {'type': 'connect', 'phase': request['phase'] + 1, 'name': request['name'],
                   'ciphers': [sender.sa_data['cipherspec']],
                   'data': {'cif': base64.b64encode(msg_cifrada),
                            'IV': iv,
                            'salt-cifra': base64.b64encode(salt_cifra),
                            'salt-hash': base64.b64encode(salt_hmac)}}

            signed = utilsAES.signServer(self.priv_k, json.dumps(msg, sort_keys=True))

            msg['data']['signed'] = base64.b64encode(signed)

            sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

            sender.send(msg)
            logging.info("Regeneration of Secret - continue to phase " + str(msg['phase']))
            sender.sa_data['start_time'] = time.time()
            sender.state = STATE_CONNECTED
            sender.sa_data['count'] = 0
            return

        if request['phase'] == 9:

            hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
            ack = {'type': 'ack', 'hash': hash_to_send}
            signed = utilsAES.signServer(self.priv_k, json.dumps(ack, sort_keys=True))
            ack['signed'] = base64.b64encode(signed)
            sender.send(ack)

            if utilsAES.verificarAssinatura_Generic(request, sender.cert, 'data') == False:
                logging.error("Assinatura de Mensagem Inválida!")
                self.delClient(sender.socket)
                sender.close()
                return

            recebido = request['data']
            msg_decifrada = self.decipherMessage(base64.b64decode(recebido['salt-cifra']),
                                                 base64.b64decode(recebido['salt-hash']),
                                                 recebido['IV'],
                                                 sender.sa_data['segredo'],
                                                 base64.b64decode(recebido['cif']),
                                                 sender.sa_data['cipherspec'],
                                                 sender)

            sender.sa_data['ids'][request['id']] = request

            if recebido['id'] in self.id2client.keys():
                client_id = self.generate_nonce()
                sender.id = client_id
                salt_cifra, salt_hmac, iv, msg_cifrada = self.cipherMessage(sender.sa_data['segredo'],
                                                                            json.dumps(
                                                                                {'id': client_id,
                                                                                 'level': sender.level}),
                                                                            sender.sa_data[
                                                                                'cipherspec'])
                msg = {'type': 'connect', 'phase': request['phase'] + 1, 'name': request['name'],
                       'ciphers': [sender.sa_data['cipherspecs']],
                       'data': {'id': base64.b64encode(msg_cifrada),
                                'IV': iv,
                                'salt-cifra': base64.b64encode(salt_cifra),
                                'salt-hash': base64.b64encode(salt_hmac)}}

                signed = utilsAES.signServer(self.priv_k, json.dumps(msg, sort_keys=True))

                msg['data']['signed'] = base64.b64encode(signed)

                sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

                sender.send(msg)
            else:
                sender.id = recebido['id']
                salt_cifra, salt_hmac, iv, msg_cifrada = self.cipherMessage(sender.sa_data['segredo'],
                                                                            json.dumps(
                                                                                {'valid': 'OK',
                                                                                 'level': sender.level}),
                                                                            sender.sa_data[
                                                                                'cipherspec'])
                msg = {'type': 'connect', 'phase': request['phase'] + 1, 'name': request['name'],
                       'ciphers': [sender.sa_data['cipherspec']],
                       'data': {'id': base64.b64encode(msg_cifrada),
                                'IV': iv,
                                'salt-cifra': base64.b64encode(salt_cifra),
                                'salt-hash': base64.b64encode(salt_hmac)}}

                signed = utilsAES.signServer(self.priv_k, json.dumps(msg, sort_keys=True))

                msg['data']['signed'] = base64.b64encode(signed)

                sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

                sender.send(msg)

        self.id2client[sender.id] = sender
        sender.bi = utilsAES.getNBI(sender.cert)
        self.lapadula[sender.id] = self.id2client[sender.id].level
        self.dict_certs[sender.id] = sender.cert
        self.id2client[sender.id] = sender
        sender.name = request['name']
        sender.state = STATE_CONNECTED
        sender.sa_data['start_time'] = time.time()
        sender.sa_data['count'] = 0
        logging.info("Client %s Connected" % request['id'])

    def processDisDonnect(self, sender, request):
        '''
        Função utilizada para disconnctar o cliente do servidor

        O servidor responde com um campo VALID no DATA a dizer OK, o cliente quando vê que recebe esta mensagem, que vai cifrada, sabe que está desconectado e pode-se desligar.

        Depois de enviada a mensagem, o cliente é apagado após ser esvaziado o BuffOut.
        :param sender:
        :param request:
        :return:
        '''

        msg_enc = {'type': 'disconnect', 'data': {'valid': 'OK'}}

        signed = utilsAES.signServer(self.priv_k, json.dumps(msg_enc, sort_keys=True))

        msg_enc['data']['signed'] = base64.b64encode(signed)

        salt_cifra, salt_hmac, iv, request_cifrado = self.cipherMessage(sender.sa_data['segredo'],
                                                                        json.dumps(msg_enc),
                                                                        sender.sa_data['cipherspec'])
        msg = {'type': 'secure',
               'sa-data': {'salt-cifra': base64.b64encode(salt_cifra), 'salt-hash': base64.b64encode(salt_hmac),
                           'IV': iv},
               'payload': {'msg': base64.b64encode(request_cifrado)}}

        signed = utilsAES.signServer(self.priv_k, json.dumps(msg, sort_keys=True))

        sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

        msg['sa-data']['signed'] = base64.b64encode(signed)

        sender.send(msg)
        self.to_delete[sender.socket] = ''
        return

    def processList(self, sender, request):
        '''
        Envia a lista de clientes conectados ao cliente caso ele tenha feito um pedido LIST

        A resposta é cifrada com os dados seguros de ambos.
        :param sender:
        :param request:
        :return:
        '''
        if sender.state != STATE_CONNECTED:
            logging.warning("LIST from disconnected client: %s" % sender)
            return

        msg = {'type': 'list', 'data': {'msg':self.clientList()}}

        signed = utilsAES.signServer(self.priv_k, json.dumps(msg, sort_keys=True))

        msg['data']['signed'] = base64.b64encode(signed)

        salt_cifra, salt_hmac, iv, cifrada = self.cipherMessage(sender.sa_data['segredo'], json.dumps(msg, sort_keys=True),
                                                                sender.sa_data['cipherspec'])

        msg = {'type': 'secure', 'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                             'salt-hash': base64.b64encode(salt_hmac)},
               'payload': {'msg': base64.b64encode(cifrada)}}

        signed = utilsAES.signServer(self.priv_k, json.dumps(msg, sort_keys=True))

        sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

        msg['sa-data']['signed'] = base64.b64encode(signed)


        sender.send(msg)

    def processSecure(self, sender, request):
        '''
        Processa uma mensagem segura de um cliente

        Aqui são actualizados os contadores de mensagem de sessão Segura. Quando chegarem 30 mensagens, o segredo entre
        o cliente e o Servidor é novamente calculado. Anulando a possibilidade das sessões de mensagens antigas serem comprometidas.

        É feito o encaminhamento do tipo de mensagem para a função onde essa mensagem é "tratada".

        :param sender:
        :param request:
        :return:
        '''

        if sender.state != STATE_CONNECTED:
            logging.warning("SECURE from disconnected client: %s" % sender)
            return

        if 'payload' not in request:
            logging.warning("Secure message with missing fields")
            return

        if utilsAES.verificarAssinatura_Generic(request, sender.cert, 'sa-data') == False:
            logging.error("Assinatura de Mensagem do tipo Secure Inválida!")
            self.delClient(sender.socket)
            sender.close()
            return

        if 'ack-list' in request['payload'].keys():
            decrypted_payload_msg = self.decipherMessage(base64.b64decode(request['sa-data']['salt-cifra']),
                                                         base64.b64decode(request['sa-data']['salt-hash']),
                                                         request['sa-data']['IV'],
                                                         sender.sa_data['segredo'],
                                                         base64.b64decode(request['payload']['ack-list']),
                                                         sender.sa_data['cipherspec'],
                                                         sender)

            decrypted_payload_msg = json.loads(decrypted_payload_msg)

            try:
                if 'signed' in decrypted_payload_msg.keys():
                    if utilsAES.verificarAck(decrypted_payload_msg, sender.cert):
                        del sender.acks_dict[base64.b64decode(decrypted_payload_msg['hash'])]
                        return
                    else:
                        logging.error("Assinatura de ACK recebido inválida!")
                        self.delClient(sender.socket)
                        sender.close()
                else:
                    del sender.acks_dict[base64.b64decode(decrypted_payload_msg['hash'])]
                    return
            except:
                logging.error("Hash invalido")
                self.delClient(sender.socket)
                sender.close()
                return




            if decrypted_payload_msg['type'] == 'ack':
                self.sendAckClient(sender, decrypted_payload_msg, self.id2client[decrypted_payload_msg['dst']])
                return
            else:
                print '\n\n\nNão devia entrar aqui\n\n\n'

        if 'ack-connect' in request['payload'].keys():


            decrypted_payload_msg = self.decipherMessage(base64.b64decode(request['sa-data']['salt-cifra']),
                                                         base64.b64decode(request['sa-data']['salt-hash']),
                                                         request['sa-data']['IV'],
                                                         sender.sa_data['segredo'],
                                                         base64.b64decode(request['payload']['ack-connect']),
                                                         sender.sa_data['cipherspec'],
                                                         sender)

            decrypted_payload_msg = json.loads(decrypted_payload_msg)

            try:
                if 'signed' in decrypted_payload_msg.keys():
                    if utilsAES.verificarAck(decrypted_payload_msg, sender.cert):
                        del sender.acks_dict[base64.b64decode(decrypted_payload_msg['hash'])]
                        return
                    else:
                        logging.error("Assinatura de ACK recebido inválida!")
                        self.delClient(sender.socket)
                        sender.close()
                else:
                    del sender.acks_dict[base64.b64decode(decrypted_payload_msg['hash'])]
                    return
            except:
                logging.error("Hash invalido")
                self.delClient(sender.socket)
                sender.close()
                return

            if decrypted_payload_msg['type'] == 'ack':
                self.sendAckClient(sender, decrypted_payload_msg, self.id2client[decrypted_payload_msg['dst']])
                return
            else:
                print '\n\n\n\n\nNão devia de entrar aqui\n\n\n\n'
                return

        if 'ack-connect-dst' in request['payload'].keys():
            decrypted_payload_msg = self.decipherMessage(base64.b64decode(request['sa-data']['salt-cifra']),
                                                         base64.b64decode(request['sa-data']['salt-hash']),
                                                         request['sa-data']['IV'],
                                                         sender.sa_data['segredo'],
                                                         base64.b64decode(request['payload']['ack-connect-dst']),
                                                         sender.sa_data['cipherspec'],
                                                         sender)



            decrypted_payload_msg = json.loads(decrypted_payload_msg)
            if decrypted_payload_msg['type'] == 'ack':
                self.sendAckClient(sender, decrypted_payload_msg, self.id2client[decrypted_payload_msg['dst']])
                return
            else:
                print '\n\n\n\n\nNão devia de entrar aqui\n\n\n\n'


        decrypted_payload_msg = self.decipherMessage(base64.b64decode(request['sa-data']['salt-cifra']),
                                                     base64.b64decode(request['sa-data']['salt-hash']),
                                                     request['sa-data']['IV'],
                                                     sender.sa_data['segredo'],
                                                     base64.b64decode(request['payload']['msg']),
                                                     sender.sa_data['cipherspec'],
                                                     sender)

        decrypted_payload_msg = json.loads(decrypted_payload_msg)

        if 'type' not in decrypted_payload_msg.keys():
            logging.warning("Secure message without inner frame type")
            return

        sender.sa_data['count'] += 1
        if sender.sa_data['count'] == 20:
            self.regenerateSecret(sender)
            sender.sa_data['count'] = 0
            return

        if decrypted_payload_msg['type'] == 'list':

            if utilsAES.verificarAssinatura_Generic(decrypted_payload_msg, sender.cert, 'data') == False:
                logging.error("Assinatura de Mensagem do tipo Secure Inválida!")
                self.delClient(sender.socket)
                sender.close()
                return

            hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
            ack = {'type': 'ack', 'hash': hash_to_send}
            signed = utilsAES.signServer(self.priv_k, json.dumps(ack, sort_keys=True))
            ack['signed'] = base64.b64encode(signed)

            ack = json.dumps(ack, sort_keys=True)

            salt_cifra, salt_hmac, iv, cifrada = self.cipherMessage(sender.sa_data['segredo'], ack,
                                                                    sender.sa_data['cipherspec'])

            secure = {'type': 'secure', 'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                                 'salt-hash': base64.b64encode(salt_hmac)},
                   'payload': {'ack-list': base64.b64encode(cifrada)}}

            signed = utilsAES.signServer(self.priv_k, json.dumps(secure, sort_keys=True))

            secure['sa-data']['signed'] = base64.b64encode(signed)

            sender.send(secure)

            self.processList(sender, request['payload'])
            return

        if decrypted_payload_msg['type'] == 'disconnect':

            if utilsAES.verificarAssinatura_Generic(decrypted_payload_msg, sender.cert, 'data') == False:
                logging.error("Assinatura de Mensagem do tipo Secure Inválida!")
                self.delClient(sender.socket)
                sender.close()
                return

            hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
            ack = {'type': 'ack', 'hash': hash_to_send}
            signed = utilsAES.signServer(self.priv_k, json.dumps(ack, sort_keys=True))
            ack['signed'] = base64.b64encode(signed)

            ack = json.dumps(ack, sort_keys=True)

            salt_cifra, salt_hmac, iv, cifrada = self.cipherMessage(sender.sa_data['segredo'], ack,
                                                                    sender.sa_data['cipherspec'])

            secure = {'type': 'secure', 'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                                    'salt-hash': base64.b64encode(salt_hmac)},
                      'payload': {'ack-connect': base64.b64encode(cifrada)}}

            signed = utilsAES.signServer(self.priv_k, json.dumps(secure, sort_keys=True))

            secure['sa-data']['signed'] = base64.b64encode(signed)

            sender.send(secure)

            self.processDisDonnect(sender, request['payload'])
            return

        if not all(k in decrypted_payload_msg.keys() for k in ("src", "dst")):
            return

        if decrypted_payload_msg['type'] == 'client-connect':
            if not decrypted_payload_msg['dst'] in self.id2client.keys():

                hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
                ack = {'type': 'ack', 'hash': hash_to_send}
                signed = utilsAES.signServer(self.priv_k, json.dumps(ack, sort_keys=True))
                ack['signed'] = base64.b64encode(signed)

                ack = json.dumps(ack, sort_keys=True)

                salt_cifra, salt_hmac, iv, cifrada = self.cipherMessage(sender.sa_data['segredo'], ack,
                                                                        sender.sa_data['cipherspec'])

                secure = {'type': 'secure', 'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                                        'salt-hash': base64.b64encode(salt_hmac)},
                          'payload': {'ack-connect': base64.b64encode(cifrada)}}

                signed = utilsAES.signServer(self.priv_k, json.dumps(secure, sort_keys=True))

                secure['sa-data']['signed'] = base64.b64encode(signed)

                sender.send(secure)

                self.warnDoesntExist(sender, decrypted_payload_msg)
                logging.warning("Message to unknown client: %s" % decrypted_payload_msg['dst'])
                return

            else:

                hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
                ack = {'type': 'ack', 'hash': hash_to_send}
                signed = utilsAES.signServer(self.priv_k, json.dumps(ack, sort_keys=True))
                ack['signed'] = base64.b64encode(signed)

                ack = json.dumps(ack, sort_keys=True)

                salt_cifra, salt_hmac, iv, cifrada = self.cipherMessage(sender.sa_data['segredo'], ack,
                                                                        sender.sa_data['cipherspec'])

                secure = {'type': 'secure', 'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                                        'salt-hash': base64.b64encode(salt_hmac)},
                          'payload': {'ack-connect': base64.b64encode(cifrada)}}

                signed = utilsAES.signServer(self.priv_k, json.dumps(secure, sort_keys=True))

                secure['sa-data']['signed'] = base64.b64encode(signed)

                sender.send(secure)

                dst = self.id2client[decrypted_payload_msg['dst']]
                self.processClientConnect(sender, decrypted_payload_msg, dst)
                return

        if decrypted_payload_msg['type'] in ['client-disconnect', 'client-com', 'ack']:
            if not decrypted_payload_msg['dst'] in self.id2client.keys():
                self.warnDoesntExist(sender, decrypted_payload_msg)
                logging.warning("Message to unknown client: %s" % decrypted_payload_msg['dst'])
                return
            dst = self.id2client[decrypted_payload_msg['dst']]



            if decrypted_payload_msg['type'] not in ['ack', 'client-disconnect']:
                destination_level = self.lapadula[decrypted_payload_msg['dst']]
                # orig_msg_level = decrypted_payload_msg['data']['level']
                orig_level = self.lapadula[decrypted_payload_msg['src']]

                hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
                ack = {'type': 'ack', 'hash': hash_to_send}
                signed = utilsAES.signServer(self.priv_k, json.dumps(ack, sort_keys=True))
                ack['signed'] = base64.b64encode(signed)

                ack = json.dumps(ack, sort_keys=True)

                salt_cifra, salt_hmac, iv, cifrada = self.cipherMessage(sender.sa_data['segredo'], ack,
                                                                        sender.sa_data['cipherspec'])

                secure = {'type': 'secure', 'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                                        'salt-hash': base64.b64encode(salt_hmac)},
                          'payload': {'ack-connect': base64.b64encode(cifrada)}}

                signed = utilsAES.signServer(self.priv_k, json.dumps(secure, sort_keys=True))

                secure['sa-data']['signed'] = base64.b64encode(signed)

                sender.send(secure)

                if (destination_level > orig_level):
                    self.sendBlockedLapadulaMsg(sender, decrypted_payload_msg, decrypted_payload_msg['dst'])
                else:
                    self.processClientGenericMsg(sender, decrypted_payload_msg, dst)
            else:

                hash_to_send = base64.b64encode(utilsAES.gerarHashMsg(json.dumps(request, sort_keys=True)))
                ack = {'type': 'ack', 'hash': hash_to_send}
                signed = utilsAES.signServer(self.priv_k, json.dumps(ack, sort_keys=True))
                ack['signed'] = base64.b64encode(signed)

                ack = json.dumps(ack, sort_keys=True)

                salt_cifra, salt_hmac, iv, cifrada = self.cipherMessage(sender.sa_data['segredo'], ack,
                                                                        sender.sa_data['cipherspec'])

                secure = {'type': 'secure', 'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                                        'salt-hash': base64.b64encode(salt_hmac)},
                          'payload': {'ack-connect': base64.b64encode(cifrada)}}

                signed = utilsAES.signServer(self.priv_k, json.dumps(secure, sort_keys=True))

                secure['sa-data']['signed'] = base64.b64encode(signed)

                sender.send(secure)

                self.processClientGenericMsg(sender, decrypted_payload_msg, dst)

    def processClientConnect(self, sender, request, dst):
        '''
        Método que trata das fases de estabelecimento de uma conexão segura entre 2 clientes.
        Esta função encontra-se dividida pelas fases de conexão entre ambos os Clientes.
        Quando é recebida a fase 1 é feito o match dois 2 ciphersuits que tanto como origem como destino suportam, de seguida, é feito um match dessa lista com o ciphersuite que a origem pediu para ser utilizado.
        Se a origem enviar os 2 ciphersuits que suporta, o servidor escolhe o mais seguro (AES256), se enviar apenas um, é esse que vai ser utilizado.
        Em resposta vai o cipherspec escolhido para fazer a conexão e processos de cifragem entre os 2 clientes.

        Nas próximas fases recebidas apenas é feita a cifra para o destino, ou seja, só há encaminhamento no canal seguro.
        :param sender:
        :param request:
        :param dst:
        :return:
        '''
        if dst.state != STATE_CONNECTED:
            logging.warning("CLIENT-CONNECT from a disconnected Client: %s" % sender)
            return

        if 'phase' not in request.keys():
            logging.warning("Client-connect message with missing phase!")
            return

        if request['phase'] == 1:
            dst_id = request['dst']
            dst_id_cipherspecs = self.id2client[dst_id].sa_data['suportados']
            sender_cipherspecs = self.id2client[sender.id].sa_data['suportados']
            equal_cipherspecs = [x for x in sender_cipherspecs if x in dst_id_cipherspecs]

            if len(request['ciphers']) > 1:
                equal_equal_cipherspecs = [x for x in request['ciphers'] if x in equal_cipherspecs]
                if C2 in equal_equal_cipherspecs:
                    choosen_cipherspec = C2
                else:
                    choosen_cipherspec = C1
            else:
                if request['ciphers'][0] in equal_cipherspecs:
                    choosen_cipherspec = request['ciphers'][0]

            msg = {'type': 'client-connect', 'src': request['src'], 'dst': request['dst'],
                   'phase': request['phase'] + 1, 'ciphers': [choosen_cipherspec], 'data': {}}

            salt_cifra, salt_hmac, iv, request_cifrado = self.cipherMessage(sender.sa_data['segredo'],
                                                                            json.dumps(msg),
                                                                            sender.sa_data[
                                                                                'cipherspec'])

            logging.info("Connect continue to phase " + str(msg['phase']))

            secure = {'type': 'secure',
                      'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                  'salt-hash': base64.b64encode(salt_hmac)},
                      'payload': {'msg': base64.b64encode(request_cifrado)}}

            signed = utilsAES.signServer(self.priv_k, json.dumps(secure, sort_keys=True))

            sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(secure, sort_keys=True))] = 'hash'

            secure['sa-data']['signed'] = base64.b64encode(signed)

            sender.send(secure)
            return

        # Diffie-Hellman Client Client
        if request['phase'] > 2:



            salt_cifra, salt_hmac, iv, request_cifrado = self.cipherMessage(dst.sa_data['segredo'],
                                                                            json.dumps(request),
                                                                            dst.sa_data['cipherspec'])

            dst_message = {'type': 'secure',
                           'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                       'salt-hash': base64.b64encode(salt_hmac)},
                           'payload': {'msg': base64.b64encode(request_cifrado)}}
            # if request['phase'] == 3:
            #     dst_message = {'type': 'secure',
            #                    'sa-data': {'fase': '3', 'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
            #                                'salt-hash': base64.b64encode(salt_hmac)},
            #                    'payload': {'msg': base64.b64encode(request_cifrado)}}


            signed = utilsAES.signServer(self.priv_k, json.dumps(dst_message, sort_keys=True))

            dst.acks_dict[utilsAES.gerarHashMsg(json.dumps(dst_message, sort_keys=True))] = 'hash'

            dst_message['sa-data']['signed'] = base64.b64encode(signed)

            dst.send(dst_message)
            return

    def processClientGenericMsg(self, sender, request, dst):
        '''
        Função onde é efectuado o encaminhamento para o destino de mensagens do tipo ['client-disconnect', 'client-com', 'ack']
        Apenas cifro a mensagem que é suposto ir encapsulada no secure e reencaminho para o destino
        Os processos de cifragem são feitos no CipherMessage, e é dado como argumento o segredo que o Servidor e o destino partilham
        :param sender:
        :param request:
        :param dst:
        :return:
        '''
        if dst.state != STATE_CONNECTED:
            logging.warning("Message to a disconnected Client: %s" % sender)
            return

        salt_cifra, salt_hmac, iv, request_cifrado = self.cipherMessage(dst.sa_data['segredo'],
                                                                        json.dumps(request),
                                                                        dst.sa_data['cipherspec'])

        dst_message = {'type': 'secure', 'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                                     'salt-hash': base64.b64encode(salt_hmac)},
                       'payload': {'msg': base64.b64encode(request_cifrado)}}

        signed = utilsAES.signServer(self.priv_k, json.dumps(dst_message, sort_keys=True))

        dst.acks_dict[utilsAES.gerarHashMsg(json.dumps(dst_message, sort_keys=True))] = 'hash'

        dst_message['sa-data']['signed'] = base64.b64encode(signed)

        dst.send(dst_message)
        return

    def cipherMessage(self, secret, msg_before, cipherspec):
        '''
        Função genérica utilizada no processo de cifragem de mensagens.
        :param secret: Segredo partilhado entre ambas as partes
        :param msg_before:  Texto a cifrar
        :param cipherspec: Decide que ciphersuit utilizar para a cifra. AES128 ou AES256
        :return: Os salts utilizados para derivar as chaves de cifra e do HMAC, o IV utilizado no processo de cifra, o hmac gerado sobre a mensagem, e o texto cifrado.
        '''
        my_salt_cifra = os.urandom(16)
        my_salt_hmac = os.urandom(16)
        iv = utilsAES.generateIV()
        chave_derivada_cifra = utilsAES.derivate(secret, my_salt_cifra, cipherspec)
        chave_derivada_hmac = utilsAES.derivate(secret, my_salt_hmac, cipherspec)
        request_cifrado = utilsAES.encryptAES(chave_derivada_cifra, msg_before, iv)
        hash_msg_before = utilsAES.generateHashMsg(chave_derivada_hmac, request_cifrado)

        return my_salt_cifra, my_salt_hmac, base64.b64encode(iv), request_cifrado + hash_msg_before

    def decipherMessage(self, salt_cifra, salt_hmac, iv, secret, ciphertext, cipherspec, sender):
        '''
        Função genérica utilizada para a decifra de mensagens e verificação de hmacs
        Caso levante uma exceçao quer dizer que a mensagem foi alterada pelo caminho
        :param salt_cifra: Random utilizado para derivar o segredo numa chave com um dado tamanho (32 ou 16), que irá ser utilizada para decifrar mensagens
        :param salt_hmac: Random utilizado para derivar o segredo numa chave com um dado tamanho, que irá ser dada á função que cria o hmac
        :param iv: IV utilizado no processo de decifra
        :param secret:  Chave secreta partilhada entre ambas as partes
        :param text: Texto a decifrar
        :param cipherspec: Decide que ciphersuite usamos. AES256 ou AES128.
        :return: Mensagem decifrada
        '''
        chave_derivada_cifra = utilsAES.derivate(secret, salt_cifra, cipherspec)
        chave_derivada_hmac = utilsAES.derivate(secret, salt_hmac, cipherspec)
        try:
            hash_verify = utilsAES.VerifyHashMsg(chave_derivada_hmac, ciphertext[:-32], ciphertext[-32:])
        except:
            logging.error('A mensagem foi adulterada')
            self.delClient(sender.socket)
            sender.close()
        msg_decifrada = utilsAES.decryptAES(chave_derivada_cifra, ciphertext[:-32], base64.b64decode(iv))
        return msg_decifrada

    def generateSecret(self, priv_k, peer_pub_key):
        '''
        Função utilizada para gerar um segredo comum entre as duas partes
        :param priv_k:Chave privada do servidor com aquele cliente
        :param peer_pub_key: Chave pública recebida pelo servidor (a do client)
        :return:
        '''
        return priv_k.exchange(ec.ECDH(), peer_pub_key)

    def generate_nonce(self, length=8):
        """Generate pseudorandom number."""
        nonce = ''.join([str(random.randint(0, 9)) for i in range(length)])
        if nonce in self.id2client.keys():
            self.generate_nonce()
        return nonce

    def warnDoesntExist(self, sender, request):
        '''
        Tipo de mensagem que é enviada para o cliente quando é recebido um client-connect de um ID ao qual o servidor
        não está conectado
        É cifrada a mensagem com uma derivação do segredo, e é gerado o hmac de outra derivação do segredo
        :param sender: instancia do cliente
        :param request: pedido feito
        :return:
        '''
        if request['type'] == 'client-connect':
            msg = {'type': request['type'], 'src': request['src'], 'dst': request['dst'], 'phase': 99, 'ciphers': [],
                   'data': 'doesntexist'}
        else:
            msg = {'type': request['type'], 'src': request['src'], 'dst': request['dst'], 'ciphers': [],
                   'data': 'doesntexist'}

        salt_cifra, salt_hmac, iv, request_cifrado = self.cipherMessage(
            sender.sa_data['segredo'],
            json.dumps(msg),
            sender.sa_data[
                'cipherspec'])

        sender.send(
            {'type': 'secure',
             'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                         'salt-hash': base64.b64encode(salt_hmac)},
             'payload': {'msg': base64.b64encode(request_cifrado)}})
        return

    def regenerateSecret(self, sender):
        '''
        Função utilizada para renovar o segredo entre o cliente o servidor
        A renovação pode ser devido à expiração do tempo de vida da sessão ou devido a ter sido atingido
        o número de mensagens permitido por sessão
        :param sender:
        :return:
        '''
        msg = {'type': 'connect', 'phase': 1, 'name': sender.name,
               'ciphers': [sender.sa_data['cipherspec']],
               'data': {'certificate': base64.b64encode(self.certificate)}}

        logging.info("Connect continue to phase " + str(msg['phase']))

        sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(msg, sort_keys=True))] = 'hash'

        sender.state = STATE_DISCONNECTED
        sender.send(msg)
        return

    def sendBlockedLapadulaMsg(self, sender, decrypted_payload_msg, dst):
        if sender.state != STATE_CONNECTED:
            logging.warning("Message to a disconnected Client: %s" % sender)
            return

        salt_cifra, salt_hmac, iv, request_cifrado = self.cipherMessage(sender.sa_data['segredo'],
                                                                        json.dumps({'type':'LAPADULA-ERROR','dst':dst}),
                                                                        sender.sa_data['cipherspec'])

        dst_message = {'type': 'secure', 'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                                     'salt-hash': base64.b64encode(salt_hmac)},
                       'payload': {'msg': base64.b64encode(request_cifrado)}}

        signed = utilsAES.signServer(self.priv_k, json.dumps(dst_message, sort_keys=True))

        sender.acks_dict[utilsAES.gerarHashMsg(json.dumps(dst_message, sort_keys=True))] = 'hash'

        dst_message['sa-data']['signed'] = base64.b64encode(signed)

        sender.send(dst_message)
        return

    def sendAckClient(self, sender, request, dst):


        salt_cifra, salt_hmac, iv, request_cifrado = self.cipherMessage(dst.sa_data['segredo'],
                                                                        json.dumps(request),
                                                                        dst.sa_data['cipherspec'])

        dst_message = {'type': 'secure', 'sa-data': {'IV': iv, 'salt-cifra': base64.b64encode(salt_cifra),
                                                     'salt-hash': base64.b64encode(salt_hmac)},
                       'payload': {'ack-connect': base64.b64encode(request_cifrado)}}

        signed = utilsAES.signServer(self.priv_k, json.dumps(dst_message, sort_keys=True))

        dst_message['sa-data']['signed'] = base64.b64encode(signed)

        dst.send(dst_message)
        return


if __name__ == "__main__":
    if len(sys.argv) > 1:
        PORT = int(sys.argv[1])

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                        formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    serv = None
    while True:
        try:
            logging.info("Starting Secure IM Server v1.0")
            serv = Server(HOST, PORT)
            serv.loop()
        except KeyboardInterrupt:
            if serv is not (None):
                serv.stop()
            try:
                logging.info("Press CTRL-C again within 2 sec to quit")
                time.sleep(2)
            except KeyboardInterrupt:
                logging.info("CTRL-C pressed twice: Quitting!")
                break
        except:
            logging.exception("Server ERROR")
            if serv is not (None):
                serv.stop()
            time.sleep(10)
