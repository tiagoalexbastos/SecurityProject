# coding=utf-8
import os
import sys

reload(sys)
sys.setdefaultencoding('utf-8')
import socket
import random
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import ec
from Crypto.Cipher import AES
import utilsAES
import base64
from cryptography.hazmat.primitives import serialization
import logging
import sys
import time
from socket import *
from select import *

TERMINATOR = "\n\n"
BUFSIZE = 512 * 1024
TERMINATOR = "\n\n"
MAX_BUFSIZE = 64 * 1024

STATE_NONE = 0
STATE_CONNECTED = 1
STATE_DISCONNECTED = 2


class Client:
    def __init__(self, name, cip):
        self.cipher = cip  # Este é o cipherspec que está em uso com o Servidor
        self.cipherspec = ['ECDHE-AES128-SHA', 'ECDHE-AES256-SHA']  # Cipherspecs que o cliente suporta
        self.status = 'DISCONNECTED'
        self.shared_key = None  # Segredo partilhado entre o cliente e o servidor (DH-elliptic curve)
        self.name = name
        self.id = None  # O id é gerado durante o handshake entre o cliente e o servidor
        self.clients_on = {}  # dicionário que irá conter as informações dos outros clientes ligados a este cliente
        self.bufin = ""
        self.bufout = ""
        self.sock = socket(AF_INET, SOCK_STREAM)
        self.bind = self.sock.bind(("127.0.0.1", 0))
        self.connect = self.sock.connect(("127.0.0.1", 8080))
        self.private_k = ec.generate_private_key(ec.SECP384R1(),
                                                 default_backend())  # chave privada do cliente para a geração do segredo com o servidor
        self.pub_k = self.private_k.public_key()  # chave pública do cliente que vai ser dada ao servidor para ele poder gerar o segredo
        self.to_delete = {}  # dicionário de clientes a eliminar após a fase "Client-Disconnect"
        self.counter = 0  # contador para estabelecer novo segredo entre os clientes quando recebe x mensagens

    def __str__(self):
        """ Converts object into string.
        """
        return "Client(name=%r status:%s)" % (self.name, self.status)

    def generate_nonce(self, length=8):
        """Generate pseudorandom number."""
        return ''.join([str(random.randint(0, 9)) for i in range(length)])

    def stop(self):
        """ Stops the server closing all sockets
               """
        logging.info("Stopping Server")
        try:
            self.sock.close()
        except:
            logging.exception("Server.stop")

        self.clients_on.clear()

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

    def loop(self):
        '''
            Esta função é baseada no código do servidor, no entanto, a nossa wlist vai ser o nosso socket, visto que
            tudo aquilo que o cliente envia tem de passar pelo servidor.

            Além dsso, o nosso rlist também tem o:  "sys.stdin" para poder receber input do utilizador pela consola e
            agir de acordo com o que o utilizador pretende

        '''

        while True:
            # logging.debug("select waiting for %dR %dW %dX", len(rlist), len(wlist), len(rlist))
            if len(self.bufout) > 0:
                wlist = [self.sock]
            else:
                wlist = []

            (rl, wl, xl) = select([self.sock, sys.stdin], wlist, [self.sock])
            # logging.debug("select: %s %s %s", rl, wl, xl)

            # Deal with incoming data:
            # if len(rl) > 0 :
            for s in rl:
                if s == self.sock:
                    self.flushin()
                elif s == sys.stdin:
                    self.OptionsMenu(sys.stdin.readline())

            # Deal with outgoing data:
            # if len(wl) > 0:
            for s in wl:
                self.flushout()

                # if len(xl) > 0:
            for s in xl:
                logging.error("EXCEPTION in %s. Closing", s)
                self.stop()

    def flushin(self):
        """Read a chunk of data from this client.
        Enqueue any complete requests.
        Leave incomplete requests in buffer.
        This is called whenever data is available from client socket.
        """

        data = None
        try:
            data = self.sock.recv(BUFSIZE)
            # logging.info("Received data. Message:\n%r", data)
        except:
            logging.error("Received invalid data from. Closing")
            self.stop()
        else:
            if len(data) > 0:
                reqs = self.parseReqs(data)
                for req in reqs:
                    self.handleRequest(req)
            else:
                self.stop()

    def flushout(self):
        """Write a chunk of data to client.            This is called whenever client socket is ready to transmit data."""

        try:
            sent = self.sock.send(self.bufout[:BUFSIZE])
            # logging.info("Sent %d bytes . Message:\n%r", sent, self.bufout[:sent])
            self.bufout = self.bufout[sent:]  # leave remaining to be sent later

            '''
                É no flushout que apagamos toda a informação sobre os utilizadores que estavam conectados a este.

                Isto porque ao apagarmos os dados do cliente logo quando estavamos a trocar fases, ia fazer com que ao enviar a ultima
                mensagem os dados do cliente ja nao estivessem disponiveis.

                Dessa forma, decidimos guardar num dicionario (self.to_delete)extra o id dos clientes que vao ser desconectados. E aqui apagamos a informação
                referente aos mesmos(self.clients_on)
            '''

            if len(self.to_delete) > 0:
                for k in self.to_delete.keys():
                    del self.clients_on[k]
                self.to_delete = {}


        except:
            # logging.error("Cannot write to client %s. Closing", client)
            self.stop()

    def handleRequest(self, request):
        """Handle a request from a client socket.
        """

        try:
            # logging.info("HANDLING message: %r", repr(request))

            try:
                req = json.loads(request)
            except:
                return

            if not isinstance(req, dict):
                return

            if 'type' not in req:
                return

            if req['type'] == 'ack':
                return  # Ignore for now

            self.send({'type': 'ack'})
            if req['type'] == 'connect':
                self.processConnect(req)
            elif req['type'] == 'secure':
                self.processSecure(req)

        except Exception, e:
            logging.exception("Could not handle request")

    def send(self, obj):
        """Send an object to this client.
        """
        try:
            self.bufout += json.dumps(obj) + "\n\n"
        except:
            # It should never happen! And not be reported to the client!
            logging.exception("Client.send(%s)", self)

    def processConnect(self, req):

        '''
        A função processConnect serve para controlar o envio e recepção de mensagens na fase de
        HANDSHAKE entre este cliente e o servidor.

        A primeira parte deste Handshake trata de acordar o cipherspec que será utilizador.
        O utilizador envia o que pretende e se este corresponde a algum do cipherspec do servidor, é esse que será
        usado. Caso o utilizador nao queira, é o servidor que escolhe a que tiver maior valor criptográfico.
        PS: Esta escolher é feita logo na main através de input

        A segunda parte consiste em acordar um segredo com o servidor através de DH elliptic curve

        A terceira parte consiste em cifrar uma mensagem e enviar o HMAC(feito com a mensagem antes de ser cifrada).
        Se o servidor conseguir gerar um HMAC igual ao que nossos enviamos(através da mensagem decifrada) isso quer dizer que a decifra foi bem
        sucedida e por isso o handshake pode ser finalizado.
        O servidor faz o mesmo para o cliente, e este tem de conseguir chegar ao mesmo valor de HMAC

        Após isto o HANDSHAKE cliente-servidor é concluido.


        :param req: tras a informação da mensagem recebida
        '''

        phase = req['phase']

        if phase == 1:

            self.private_k = ec.generate_private_key(ec.SECP384R1(), default_backend())
            self.pub_k = self.private_k.public_key()

            sk = utilsAES.loadPublicKey(str(req['data']['pub']))
            self.shared_key = self.private_k.exchange(ec.ECDH(), sk)

            msg = {'name': self.name, 'type': 'connect', 'phase': phase + 1, 'ciphers': self.cipher,
                   'id': self.generate_nonce(),
                   'data': {'pub': utilsAES.serializePublicKey(self.pub_k)}}
            data = json.dumps(msg)
            self.sock.send(data + "\n\n")
            return

        if phase == 2:

            cipher = req['ciphers']

            if len(cipher) == 0:
                logging.error("Cipherspecs do not match. Impossible to make a connection.")
                os._exit(1)

            if len(req['ciphers']) == 2 and len(self.cipher) == 2:
                self.cipher = self.cipherspec[1]


            elif self.cipher[0] in req['ciphers']:
                self.cipher = self.cipher[0]

            else:
                logging.error("Cipherspecs do not match. Impossible to make a connection.")
                os._exit(1)

            msg = {'name': self.name, 'type': 'connect', 'phase': phase + 1, 'ciphers': self.cipher,
                   'id': self.generate_nonce(),
                   'data': {'pub': utilsAES.serializePublicKey(self.pub_k)}}
            data = json.dumps(msg)
            self.sock.send(data + TERMINATOR)
            return

        if phase == 3:
            hash_msg_dec, decrypted_payload_msg = self.DecipherMessage(base64.b64decode(req['data']['IV']),
                                                                       base64.b64decode(req['data']['cif']),
                                                                       base64.b64decode(req['data']['salt-cifra']),
                                                                       base64.b64decode(req['data']['salt-hash']),
                                                                       self.shared_key,
                                                                       self.cipher)

            if hash_msg_dec == 'OK':

                msg_before = "ola"

                IV_sending, msg_cifrada, salt_cifra, salt_hmac = self.GenerateCipherParameters(
                    self.shared_key, msg_before, self.cipher)

                msg = {'name': self.name, 'type': 'connect', 'phase': phase + 1, 'ciphers': self.cipher,
                       'id': self.generate_nonce(),
                       'data': {'cif': msg_cifrada, 'salt-cifra': salt_cifra, 'salt-hash': salt_hmac,
                                'IV': IV_sending, 'id': self.id}}

                data = json.dumps(msg)
                self.sock.send(data + "\n\n")
                return
            else:
                logging.warning("Conecção com o servidor invalida. Vamos começar de novo.")
                msg = {'name': self.name, 'type': 'connect', 'phase': 1, 'ciphers': self.cipher,
                       'id': self.id, 'data': {}}
                data = json.dumps(msg)
                self.sock.send(data + TERMINATOR)

                return

        if phase == 4:
            sk = utilsAES.loadPublicKey(str(req['data']['pub']))
            self.shared_key = self.private_k.exchange(ec.ECDH(), sk)

            msg_before = "ola"

            IV_sending, msg_cifrada, salt_cifra, salt_hmac = self.GenerateCipherParameters(self.shared_key,
                                                                                                     msg_before,
                                                                                                     self.cipher)

            msg = {'name': self.name, 'type': 'connect', 'phase': phase + 1, 'ciphers': self.cipher,
                   'id': self.generate_nonce(),
                   'data': {'cif': msg_cifrada, 'salt-cifra': salt_cifra, 'salt-hash': salt_hmac,
                            'IV': IV_sending}}
            data = json.dumps(msg)
            self.sock.send(data + "\n\n")
            return

        if phase == 5:
            hash_msg_dec, decrypted_payload_msg = self.DecipherMessage(base64.b64decode(req['data']['IV']),
                                                                       base64.b64decode(req['data']['cif']),
                                                                       base64.b64decode(req['data']['salt-cifra']),
                                                                       base64.b64decode(req['data']['salt-hash']),
                                                                       self.shared_key,
                                                                       self.cipher)

            if hash_msg_dec == 'OK':

                if decrypted_payload_msg == 'ERROR':
                    logging.info("Erro na geração de segredo. Impossível connectar ao servidor")
                    os._exit(1)
                    return

                else:
                    self.status = "CONNECTED"
                    self.DisplayOptions()
                    logging.info(
                        "\n\nTempo default ou número de mensages excedido.\nPor sua precaução vamos estabelecer novos segredos.")
                    logging.info("\nNova conecção comlpleta! Client connectado com o servidor")
                    return

            else:
                logging.info("Erro na geração de segredo. Impossível connectar ao servidor.Vamos estabelecer nova coneçao")
                msg = {'name': self.name, 'type': 'connect', 'phase': 1, 'ciphers': self.cipher,
                       'id': self.id, 'data': {}}
                data = json.dumps(msg)
                self.sock.send(data + TERMINATOR)
                return

        if phase == 6:

            hash_msg_dec, decrypted_payload_msg = self.DecipherMessage(base64.b64decode(req['data']['IV']),
                                                                       base64.b64decode(req['data']['cif']),
                                                                       base64.b64decode(req['data']['salt-cifra']),
                                                                       base64.b64decode(req['data']['salt-hash']),
                                                                       self.shared_key,
                                                                       self.cipher)

            if hash_msg_dec == 'OK':

                msg_before = "ola"

                IV_sending, msg_cifrada, salt_cifra, salt_hmac = self.GenerateCipherParameters(
                    self.shared_key, msg_before, self.cipher)

                self.id = self.generate_nonce()

                msg = {'name': self.name, 'type': 'connect', 'phase': phase + 1, 'ciphers': self.cipher,
                       'id': self.generate_nonce(),
                       'data': {'cif': msg_cifrada, 'salt-cifra': salt_cifra, 'salt-hash': salt_hmac,
                                'IV': IV_sending, 'id': self.id}}

                data = json.dumps(msg)
                self.sock.send(data + "\n\n")
                self.status = "CONNECTED"
                self.DisplayOptions()

                logging.info("Client connectado com o servidor")
                return
            else:
                logging.info("Erro na geração de segredo. Impossível connectar ao servidor.Vamos estabelecer nova coneçao")
                msg = {'name': self.name, 'type': 'connect', 'phase': 1, 'ciphers': self.cipher,
                       'id': self.id, 'data': {}}
                data = json.dumps(msg)
                self.sock.send(data + TERMINATOR)
                return

        if phase == 8:

            hash_msg_dec, decrypted_payload_msg = self.DecipherMessage(base64.b64decode(req['data']['IV']),
                                                                       base64.b64decode(req['data']['id']),
                                                                       base64.b64decode(req['data']['salt-cifra']),
                                                                       base64.b64decode(req['data']['salt-hash']),
                                                                       self.shared_key,
                                                                       self.cipher)

            if hash_msg_dec == 'OK':
                if 'id' in json.loads(decrypted_payload_msg).keys():
                    self.id = decrypted_payload_msg['id']

            else:
                logging.info(
                    "Erro na geração de segredo. Impossível connectar ao servidor.Vamos estabelecer nova coneçao")
                msg = {'name': self.name, 'type': 'connect', 'phase': 1, 'ciphers': self.cipher,
                       'id': self.id, 'data': {}}
                data = json.dumps(msg)
                self.sock.send(data + TERMINATOR)
                return


    def processSecure(self, req):

        if 'payload' not in req:
            logging.warning("Secure message with missing fields")
            return

        # This is a secure message.
        # Inner message is encrypted for us. Must decrypt and validate.

        hash_msg_dec, decrypted_payload_msg = self.DecipherMessage(base64.b64decode(req['sa-data']['IV']),
                                                                   base64.b64decode(req['payload']['msg']),
                                                                   base64.b64decode(req['sa-data']['salt-cifra']),
                                                                   base64.b64decode(req['sa-data']['salt-hash']),
                                                                   self.shared_key,
                                                                   self.cipher)

        if hash_msg_dec != 'OK':
            logging.warning('A mensagem foi adulterada')
            self.stop()
            return

        decrypted_payload_msg = json.loads(decrypted_payload_msg)
        if not 'type' in decrypted_payload_msg.keys():
            logging.warning("Secure message without inner frame type")
            return


        if 'doesntexist' == decrypted_payload_msg['data']:
            self.ClientGotRekt(decrypted_payload_msg)
            return

        if decrypted_payload_msg['type'] == 'list':
            self.processList(decrypted_payload_msg['data'])
            return

        if decrypted_payload_msg['type'] == 'client-connect':
            self.processClientConnect(decrypted_payload_msg)
            return

        if decrypted_payload_msg['type'] == 'ack':
            self.recvAck(decrypted_payload_msg)

        if decrypted_payload_msg['type'] == 'disconnect':
            self.processServerDisconnect(decrypted_payload_msg)
            return

        if decrypted_payload_msg['type'] == 'client-disconnect':
            self.processClientDisconnect(decrypted_payload_msg)
            return

        if decrypted_payload_msg['type'] == 'client-com':
            self.sendAck(decrypted_payload_msg)
            self.processRecvMsg(decrypted_payload_msg)
            return


    def ClientGotRekt(self,req):

        logging.warning("O cliente "+ req['dst'] + " não existe!")

        if req['dst'] in self.clients_on.keys():
            del self.clients_on[req['dst']]

        self.GetList()


    def recvAck(self, req):
        '''
        Quando estamos a fazer troca de mensagens do tipo "client-com", o cliente que envia a mensagem
        tem de receber um ack a dizer que a mensagem foi entregue ao cliente destino.

        Esta função gere esses acks e mostra-os ao utilizador.

        :param req: conteúdo da mensagem que chegou pelo socket
        :return:
        '''

        dst_id = req['src']

        if (dst_id not in self.to_delete.keys()) and (dst_id in self.clients_on.keys()):

            segredo = self.clients_on[dst_id]['secret']

            hash_new_client, msg_dec_client = self.DecipherMessage(base64.b64decode(req['data']['IV']),
                                                                   base64.b64decode(req['data']['cif']),
                                                                   base64.b64decode(req['data']['salt-cifra']),
                                                                   base64.b64decode(req['data']['salt-hash']),
                                                                   segredo,
                                                                   self.clients_on[dst_id]['cipher'])

            if hash_new_client == 'OK':
                print "\n\nA nossa mensagem foi enviada com sucesso para o cliente: " + self.clients_on[dst_id]['name']


            else:
                print "\n\nA nossa mensagem não foi enviada para o cliente: " + self.clients_on[dst_id]['name']



    def sendAck(self, req):
        '''
        Quando estamos a fazer troca de mensagens do tipo "client-com", o cliente que recebe a mensagem
        tem de enviar um ack para a source da msg a dizer que a mensagem foi recebida

        Esta função gere esses acks e enviao ao cliente.
        :param req: conteúdo da mensagem que chegou pelo socket
        :return:
        '''

        dst_id = req['src']

        if (dst_id not in self.to_delete.keys()) and (dst_id in self.clients_on.keys()):
            segredo = self.clients_on[dst_id]['secret']

            IV_sending, msg_cifrar, salt_cifra, salt_hash = self.GenerateCipherParameters(segredo, "ack",
                                                                                                  self.clients_on[
                                                                                                      dst_id]['cipher'])

            msg = {'type': 'ack', 'src': self.id, 'dst': dst_id,
                   "data": {"IV": IV_sending, "cif": msg_cifrar,
                            "salt-cifra": salt_cifra, "salt-hash": salt_hash}}

            msg = json.dumps(msg)

            # mensagem cifrada

            IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                             self.cipher)

            secure = {"type": "secure",
                      "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra, "salt-hash": salt_hash},
                      "payload": {"msg": msg_c}}

            data = json.dumps(secure)
            self.sock.send(data + "\n\n")

    def processRecvMsg(self, msg_ser):
        '''
        Esta função trata de imprimir as mensagens recebidas do tipo ""client-com" e mostra o nome do cliente que a enviou

        Para termos a certeza que a mensagem nao foi adulterado e vem mesmo do source, temos de decifrar a mensagem e verificar
        se o HMAC que geramos é igual o HMAC enviado pelo source antes da mensagem ter sido cifrada.

        Se os HMAC corresponderem, vamos imprimir a mensagem.

        :param msg_ser: conteúdo da mensagem que chegou pelo socket
        :return:
        '''

        id_src = msg_ser["src"]

        peer_client = self.clients_on[id_src]

        hash_new_client, msg_dec_client = self.DecipherMessage(base64.b64decode(msg_ser['data']['IV']),
                                                               base64.b64decode(msg_ser['data']['cif']),
                                                               base64.b64decode(msg_ser['data']['salt-cifra']),
                                                               base64.b64decode(msg_ser['data']['salt-hash']),
                                                               peer_client['secret'],
                                                               peer_client['cipher'])

        if hash_new_client == 'OK':
            logging.info("\n\nMensagem recebida de " + peer_client['name'] + ": %s \n", msg_dec_client)

            peer_client['counter'] += 1

            elapsed_time = time.time() - peer_client['time']

            if elapsed_time > 600:
                self.NewClientKeys(id_src)
            elif peer_client['counter'] >= 20:
                self.NewClientKeys(id_src)

            return
        else:
            logging.warning("\n\nMensagem recebida de " + peer_client['name'] + " foi adulterada!\nVamos estabelecer nova ligação ao servidor \n")
            msg = {'name': self.name, 'type': 'connect', 'phase': 1, 'ciphers': self.cipher,
                   'id': self.id, 'data': {}}
            data = json.dumps(msg)
            self.sock.send(data + TERMINATOR)
            return



    def NewClientKeys(self, id):
        '''
        Esta função só é utilizada para começar uma nova geração de chaves entre dois clientes quando um destes dois fatores é ativado:
            -> O tempo de coneção foi ultrapassado e é preciso gerar novas chaves
            -> O número de mensagens "permitidas" foi ultrapassado e é preciso gerar novas chaves

        Usamos esta função porque já nao é preciso acordar o cipherspec, apenas é preciso gerar novas chaves!

        Devido a esse aspecto, esta mensagem vai ser "forçada" a estar na fase 5 porque tudo o que esta para trás(ciphers) já foi
        previamente definido.


        :param id: id do cliente que se está a ligar
        :return:
        '''

        logging.info("Tempo expirou. Nova coneção entre clientes.")

        peer_client = self.clients_on[id]

        # o nosso segredo  (alfa)
        private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
        # chave publica
        peer_public_key = private_key.public_key()

        peer_client['private_key'] = private_key
        peer_client['public_key'] = peer_public_key

        msg = {'type': 'client-connect', "src": self.id, "dst": id, "phase": 5,
               "ciphers": [peer_client['cipher']],
               'data': {'pub': utilsAES.serializePublicKey(peer_public_key), 'name': self.name}}

        msg = json.dumps(msg)

        # mensagem cifrada
        IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                           self.cipher)

        secure = {"type": "secure",
                  "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra, 'salt-hash': salt_hash},
                  "payload": {"msg": msg_c}}

        data = json.dumps(secure)
        self.sock.send(data + "\n\n")

    def processClientDisconnect(self, msg_ser):
        '''
        Esta função é usada para desconectar dois clientes.

        O cliente que começa este processo envia uma mensagem cifrada e o cliente que recebe tem de decifrar e gerar o hmac
        e confirmar o disconnect, enviando uma ultima fase apenas de confirmação

        :param msg_ser:
        :return:
        '''
        if 'flag' in msg_ser['data'].keys():
            flag = msg_ser['data']['flag']

            if flag == 1:
                del self.clients_on[msg_ser["src"]]
                return

        phase = msg_ser['data']['phase']

        if phase == 1:

            id_src = msg_ser["src"]

            # def DecipherMessage(self,iv,msg,salt,secret):

            peer_client = self.clients_on[id_src]

            hash_new_client, msg_dec_client = self.DecipherMessage(base64.b64decode(msg_ser['data']['IV']),
                                                                   base64.b64decode(msg_ser['data']['cif']),
                                                                   base64.b64decode(msg_ser['data']['salt-cifra']),
                                                                   base64.b64decode(msg_ser['data']['salt-hash']),
                                                                   peer_client['secret'],
                                                                   peer_client['cipher'])

            if hash_new_client == 'OK':

                msg_before = "Disconnect"

                IV_sending, msg_cifrar, salt_cifra, salt_hash = self.GenerateCipherParameters(
                    peer_client['secret'], msg_before, peer_client['cipher'])

                msg = {"type": "client-disconnect", "src": self.id,
                       "dst": id_src, "data": {'cif': msg_cifrar, 'salt-cifra': salt_cifra, 'salt-hash': salt_hash,
                                              'IV': IV_sending, 'phase': phase + 1}}

                msg = json.dumps(msg)

                # mensagem cifradaa


                IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                                   self.cipher)

                secure = {"type": "secure", "sa-data": {"IV": IV_sending,
                                                        "salt-cifra": salt_cifra, 'salt-hash': salt_hash},
                          "payload": {"msg": msg_c}}

                data = json.dumps(secure)
                self.sock.send(data + "\n\n")
                self.to_delete[id_src] = 'lixo'

                logging.info("\n\nCliente " + id_src + " foi desconnectado.")


            else:
                logging.warning('Impossible to disconnect because msg isnt from the source. ')

                #apagar as ligações ao cliente quebrado
                del self.clients_on[id_src]

                msg = {'name': self.name, 'type': 'connect', 'phase': 1, 'ciphers': self.cipher,
                       'id': self.id, 'data': {}}
                data = json.dumps(msg)
                self.sock.send(data + TERMINATOR)
                return

        if phase == 2:
            id_src = msg_ser["src"]
            self.to_delete[id_src] = 'lixo'

            logging.info("\n\nCliente " + id_src + " foi desconnectado.")

            self.DisplayOptions()

        return

    def processServerDisconnect(self, msg_ser):
        '''
        Após receber confirmação do servidor para haver a disconecção, informamos o utilizador que o cliente vai fechar e desligamos
        com o os._exit(1)

        :param msg_ser:
        :return:
        '''

        data = msg_ser['data']['valid']

        if data == "OK":

            self.status = "DISCONNECT"
            logging.warning('Disconnected from server...')
            os._exit(1)

        else:
            logging.warning('Disconnect error. Still connected')

        return

    def processClientConnect(self, msg_ser):
        '''
        Esta função representa a fase de conecção entre dois clientes.

        A estrutura das fases é muito parecida ao handshake cliente-servidor

        Começamos por enviar uma mensagem ao servidor com o tipo "client-connect".
        Como o servidor tem informação sobre as cifras que cada cliente pode utilizador(informação fornecida no cliente-servidor handshake)
        o servidor vai verificar se as cifras que fornecemos dão match com as cifras do cliente a que nos queremos ligar.

        Ao haver match, podemos criar um conjunto de chaves para gerar um segredo com o outro cliente.

        O resto do processo é identico, cifrar mensagens e gerar HMAC com a mensagem antes de ser cifrada, e o outro cliente
        a gerar um HMAC com a mensagem que decifra e a verificar se os HMAC's correspondem.

        A grande diferença está no facto de tudo o que os clientes comunicam entre si ir cifrado, o que faz com que o servidor
        receba as mensagens de cada um, mas seja incapaz de decifrar. Desta forma garantimos segurança e privacidade na troca de mensagens
        entre os clientes.

        :param msg_ser:
        :return:
        '''

        phase = msg_ser['phase']
        if phase == 2:

            valid_ciphers = msg_ser['ciphers']
            if len(valid_ciphers) == 0:

                if 'exists' in msg_ser['data'].keys():
                    if msg_ser['data']['exists'] == 'No':
                        logging.warning("Client do not exist. Impossible to connect.")
                else:
                    logging.warning("Cipherspecs do not match. Impossible to connect.")
                self.DisplayOptions()
                return



            else:
                msg = {"type": "client-connect", "src": self.id, "dst": msg_ser['dst'], "phase": phase + 1,
                       "ciphers": [valid_ciphers[0]], "data": ""}

            msg = json.dumps(msg)

            # mensagem cifrada


            IV_sending, msg_cifrar, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                                  self.cipher)

            secure = {"type": "secure",
                      "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra, 'salt-hash': salt_hash},
                      "payload": {"msg": msg_cifrar}}

            data = json.dumps(secure)
            self.sock.send(data + "\n\n")
            return


        elif phase == 3:

            msg = {"type": "client-connect", "src": self.id, "dst": msg_ser['src'],
                   "phase": phase + 1, "ciphers": [msg_ser['ciphers'][0]], "data": {'name': self.name}}
            msg = json.dumps(msg)

            # mensagem cifrada

            IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                               self.cipher)

            secure = {"type": "secure",
                      "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra, 'salt-hash': salt_hash},
                      "payload": {"msg": msg_c}}

            data = json.dumps(secure)
            self.sock.send(data + TERMINATOR)

            return

        elif phase == 4:

            self.clients_on[msg_ser['src']] = {}
            peer_client = self.clients_on[msg_ser['src']]
            peer_client['name'] = msg_ser['data']['name']

            # o nosso segredo  (alfa)
            private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            # chave publica
            peer_public_key = private_key.public_key()

            peer_client['private_key'] = private_key
            peer_client['public_key'] = peer_public_key
            peer_client['cipher'] = msg_ser['ciphers'][0]

            msg = {'type': 'client-connect', "src": self.id, "dst": msg_ser['src'], "phase": phase + 1,
                   "ciphers": [peer_client['cipher']],
                   'data': {'pub': utilsAES.serializePublicKey(peer_public_key), 'name': self.name}}

            msg = json.dumps(msg)

            # mensagem cifrada
            IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                               self.cipher)

            secure = {"type": "secure",
                      "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra, 'salt-hash': salt_hash},
                      "payload": {"msg": msg_c}}

            data = json.dumps(secure)
            self.sock.send(data + "\n\n")

        elif phase == 5:

            '''
            Gerar o segredo
            '''

            id_src = msg_ser["src"]
            self.clients_on[id_src] = {}
            peer_client = self.clients_on[id_src]
            peer_client['name'] = msg_ser['data']['name']

            pub_key = utilsAES.loadPublicKey(str(msg_ser["data"]["pub"]))

            # o nosso segredo  (alfa)
            private_key = ec.generate_private_key(ec.SECP384R1(), default_backend())
            # chave publica
            peer_public_key = private_key.public_key()

            peer_client['private_key'] = private_key
            peer_client['public_key'] = peer_public_key
            peer_client['secret'] = private_key.exchange(ec.ECDH(), pub_key)
            peer_client['cipher'] = msg_ser['ciphers'][0]

            '''
            Enviar a minha publica
            '''

            msg = {'type': 'client-connect', "src": self.id, "dst": id_src, "phase": phase + 1,
                   "ciphers": [peer_client['cipher']],
                   'data': {'pub': utilsAES.serializePublicKey(peer_public_key)}}

            msg = json.dumps(msg)

            # mensagem cifrada

            IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                               self.cipher)

            secure = {"type": "secure",
                      "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra, 'salt-hash': salt_hash},
                      "payload": {"msg": msg_c}}

            data = json.dumps(secure)
            self.sock.send(data + "\n\n")

        elif phase == 6:

            dest_id = msg_ser['src']

            peer_client = self.clients_on[dest_id]
            pub_key = utilsAES.loadPublicKey(str(msg_ser["data"]["pub"]))

            peer_client['secret'] = peer_client['private_key'].exchange(ec.ECDH(), pub_key)

            # enviar mensagem cifrada
            msg_before = "ola"

            IV_sending, msg_cifrada, salt_cifra, salt_hash = self.GenerateCipherParameters(
                peer_client['secret'], msg_before, peer_client['cipher'])

            msg = {'type': 'client-connect', "src": self.id, "dst": dest_id, "phase": phase + 1,
                   "ciphers": [peer_client['cipher']],
                   'data': {'cif': msg_cifrada, 'salt-cifra': salt_cifra, 'salt-hash': salt_hash,
                            'IV': IV_sending}}

            msg = json.dumps(msg)

            # mensagem cifrada

            IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                               self.cipher)

            secure = {"type": "secure",
                      "sa-data": {"IV": IV_sending,"salt-cifra": salt_cifra, 'salt-hash': salt_hash},
                      "payload": {"msg": msg_c}}

            data = json.dumps(secure)
            self.sock.send(data + "\n\n")

        elif phase == 7:

            id_src = msg_ser["src"]
            peer_client = self.clients_on[id_src]

            hash_new_client, msg_dec_client = self.DecipherMessage(base64.b64decode(msg_ser['data']['IV']),
                                                                   base64.b64decode(msg_ser['data']['cif']),
                                                                   base64.b64decode(msg_ser['data']['salt-cifra']),
                                                                   base64.b64decode(msg_ser['data']['salt-hash']),
                                                                   peer_client['secret'],
                                                                   peer_client['cipher'])

            if hash_new_client == 'OK':

                msg_before = "ola"

                IV_sending, msg_cifrar, salt_cifra, salt_hash = self.GenerateCipherParameters(
                    peer_client['secret'], msg_before, peer_client['cipher'])

                msg = {'type': 'client-connect', "src": self.id, "dst": id_src, "phase": phase + 1,
                       "ciphers": [peer_client['cipher']],
                       'data': {'cif': msg_cifrar, 'salt-cifra': salt_cifra, 'salt-hash': salt_hash,
                                'IV': IV_sending}}

                msg = json.dumps(msg)

                # mensagem cifrada

                IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                                   self.cipher)

                secure = {"type": "secure", "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra,
                                                        'salt-hash': salt_hash},
                          "payload": {"msg": msg_c}}

                data = json.dumps(secure)
                self.sock.send(data + "\n\n")

            else:
                logging.warning("Mensagem forjada, conecção ao cliente abortada! Por favor, volte a iniciar uma conecção")
                self.DisplayOptions()
                return

        elif phase == 8:

            id_src = msg_ser["src"]
            peer_client = self.clients_on[id_src]

            hash_new_client, msg_dec_client = self.DecipherMessage(base64.b64decode(msg_ser['data']['IV']),
                                                                   base64.b64decode(msg_ser['data']['cif']),
                                                                   base64.b64decode(msg_ser['data']['salt-cifra']),
                                                                   base64.b64decode(msg_ser['data']['salt-hash']),
                                                                   peer_client['secret'],
                                                                   peer_client['cipher'])

            if hash_new_client == 'OK':
                msg_before = "OK"

                IV_sending, msg_cifrar, salt_cifra, salt_hash = self.GenerateCipherParameters(
                    peer_client['secret'], msg_before, peer_client['cipher'])

                msg = {'type': 'client-connect', "src": self.id, "dst": id_src, "phase": phase + 1,
                       "ciphers": [peer_client['cipher']],
                       'data': {'cif': msg_cifrar, 'salt-cifra': salt_cifra, 'salt-hash': salt_hash,
                                'IV': IV_sending}}

                msg = json.dumps(msg)

                # mensagem cifrada


                IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                                   self.cipher)

                secure = {"type": "secure", "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra,
                                                        "salt-hash": salt_hash},
                          "payload": {"msg": msg_c}}

                data = json.dumps(secure)
                self.sock.send(data + "\n\n")
                peer_client['status'] = "CONNECTED"
                peer_client['counter'] = 0
                peer_client['time'] = time.time()
                logging.info("Client " + self.id + " connectado com o client " + id_src)
                self.DisplayOptions()
            else:
                logging.warning("Mensagem forjada, conecção ao cliente abortada! Por favor, volte a iniciar uma conecção")
                self.DisplayOptions()
            return

        elif phase == 9:

            id_src = msg_ser["src"]
            peer_client = self.clients_on[id_src]

            hash_new_client, msg_dec_client = self.DecipherMessage(base64.b64decode(msg_ser['data']['IV']),
                                                                   base64.b64decode(msg_ser['data']['cif']),
                                                                   base64.b64decode(msg_ser['data']['salt-cifra']),
                                                                   base64.b64decode(msg_ser['data']['salt-hash']),
                                                                   peer_client['secret'],
                                                                   peer_client['cipher'])

            if hash_new_client == 'OK':
                peer_client['status'] = "CONNECTED"
                peer_client['counter'] = 0
                peer_client['time'] = time.time()
                logging.info("Client " + self.id + " connectado com o client " + id_src)
                self.DisplayOptions()

            else:
                logging.warning("Mensagem forjada, conecção ao cliente abortada! Por favor, volte a iniciar uma conecção")
                self.DisplayOptions()
                return

    def processList(self, data):
        '''
        Função que vai processar a mensagem enviada pelo servidor com os clientes que estao conectados a ele.

        Ao receber esta mensagem, vamos mostrar ao utilizador o id de todos, menos o nosso próprio(visto que ele
        vem na lista dada pelo servidor)

        :param data: mensagem com todos os clientes ligados ao servidor
        :return:
        '''

        clients_list = []

        for x in data:
            if x['id'] != self.id:
                clients_list.append(x['id'])

        print "\n\n Os clientes disponiveis sao: "
        for x in clients_list:
            print "-> " + x


        for x in self.clients_on.keys():
            if x not in clients_list:
                del self.clients_on[x]

        self.DisplayOptions()

        return

    def DisplayOptions(self):
        '''
        Menu com as opções de utilização por parte do utilizador
        :return:
        '''
        print "\n\n\n"
        print 'Secure IM Client'
        print 'Lista de Comandos'
        print '-> list - Lista os ID de todos os clientes ligados ao server'
        print '-> connect#Numero#cipher - conectar ao ID com aquele número'
        print '-> send##ID##mensagem - enviar uma mensagem ao cliente com o ID especificado'
        print '-> disconnect - desconectar do servidor'
        print '-> disconnect#ID - desconectar a sessão end 2 end com o cliente com o ID especificado'
        print '-> connected - mostra todos os clientes conectados'
        print '-> ciphers - mostra os cipherspecs disponiveis'
        print '-> menu - voltar a mostrar o menu'
        print "\n\n\n"

    def OptionsMenu(self, input):
        '''
        Função para filtar o input do utilizador e garantir que este está adequado às opções existentes.

        Por outras palavras, controlo de input.
        :param input:
        :return:
        '''

        arr = input.strip("\n").split("#")
        arr2 = input.strip("\n").split("##")

        if input.strip("\n") == "list":
            self.GetList()
        elif arr[0] == "connect" and len(arr) == 3:
            self.ClientHandshake(input.strip("\n").split("#")[1], input.strip("\n").split("#")[2])
        elif input.strip("\n") == "disconnect":
            self.ServerDisconnect()
        elif arr[0] == "disconnect" and len(arr) == 2:
            self.VerifyIfConnected(input.strip("\n").split("#")[1], 0)
        elif arr2[0] == "send" and len(arr2) == 3:
            self.SendMsg(input.strip("\n").split("##")[1], input.strip("\n").split("##")[2])
        elif input.strip("\n") == "connected":
            self.ShowConnectedPeers()
        elif input.strip("\n") == "menu":
            self.DisplayOptions()
        elif input.strip("\n") == "ciphers":
            print "[1]'ECDHE-AES128-SHA'\n[2]'ECDHE-AES256-SHA'\n[3] Enviar ambos e o servidor escolher\n\n"
        else:
            logging.error("Opção Inválida!")
            self.DisplayOptions()

    def ShowConnectedPeers(self):
        '''
        Esta função serve para mostar os clientes que estão conectados com o cliente em questão.

        Desta forma o utilizador pode ver para que clientes pode enviar mensagens e as quais falta conectar-se
        :return:
        '''

        # lista de peers está em self.clients_on

        print "Lista de peers connecteds: \n"
        for k, v in self.clients_on.iteritems():
            print "  -> Id do Client: " + k
            print "  -> Nome do Client:" + v['name'] + "\n"

        self.DisplayOptions()

    def SendMsg(self, id_client, msg_escrita):
        '''
        Esta função trata de enviar as mensagens do tipo ""client-com"

        Ciframos a mensagem e enviamos um HMAC criado a partir da mensagem origal para o cliente que recebe
        a mensagem ter a certeza que esta nao foi adulterada

        :param id_client: id do cliente para o qual a mensagem vai ser enviada
        :msg_escrita: mensagem a ser enviada
        :return:
        '''

        # verificar se o id é valido

        if id_client in self.clients_on.keys():
            # ir buscar segredo partilhado

            segredo = self.clients_on[id_client]['secret']

            IV_sending, msg_cifrar, salt_cifra, salt_hash = self.GenerateCipherParameters(segredo, msg_escrita,
                                                                                                  self.clients_on[
                                                                                                      id_client][
                                                                                                      'cipher'])

            msg = {"type": "client-com", "src": self.id, "dst": id_client,
                   "data": {'cif': msg_cifrar, 'salt-cifra': salt_cifra, 'salt-hash': salt_hash,
                            'IV': IV_sending}}

            msg = json.dumps(msg)

            # mensagem cifrada

            IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                             self.cipher)

            secure = {"type": "secure",
                      "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra, "salt-hash": salt_hash},
                      "payload": {"msg": msg_c}}

            data = json.dumps(secure)
            self.sock.send(data + "\n\n")

        else:
            logging.warning("O ID que forneceu não é valido.")
            self.DisplayOptions()

    def VerifyIfConnected(self, id_client, flag):
        '''
        Verificar se o cliente a qual queremos desconectar está connectado a este cliente.
        Para impedir que seja enviado um pedido de disconnect a um cliente que nem sequer está conectado

        :param id_client: id do cliente que vamos verificar se esta no nosso dicionário com informação
        dos clientes conectados (self.clients_on:

        :param flag: flag para saber se este disconnect de cliente vem de desconectar apenas um cliente,
        ou se é um desconectar forçado pelo facto de estarmos a fazer disconnect com o servidor.

        Ou seja, ao enviarmos um disconnect apenas para o servidor, temos de enviar para os outros clientes que estão connectados connosco
        para que eles nos retirem da sua lista de clientes connectados
        :return:
        '''

        clients_con = []
        for k in self.clients_on:
            clients_con.append(k)

        if id_client in clients_con:
            self.ClientDisconnect(id_client, flag)

        else:
            logging.warning("\n\nO cliente " + str(id_client) + " não está connectado!")
            self.DisplayOptions()

    def ClientDisconnect(self, id_client, flag):

        '''
        Função que gera a primeira mensagem do fase cliente-cliente disconnect.

        Enviamos uma mensagem cifrada para o outro cliente a pedir para disconnectar.

        O principio da resposta do outro cliente é o mesmo dos outros processos..

        Criar um hmac com a mensagem que decifra e verificar se este bate certo com o hmac enviado pelo cliente.

        No entanto, esta função apenas trata do envio da primeira mensagem do cliente que começa o processo de disconnect.


        :param id_client: id do cliente que queremos disconectar

        :param flag: saber se o disconnect é do tipo "client-disconnect" ou se é um disconnect forçado pelo outro cliente se estar
        a desligar do servidor

        :return:
        '''

        # ir buscar segredo partilhado
        salt = os.urandom(16)
        segredo = self.clients_on[id_client]['secret']

        msg_before = "Disconnect"

        IV_sending, msg_cifrar, salt_cifra, salt_hash = self.GenerateCipherParameters(segredo, msg_before,
                                                                                              self.clients_on[
                                                                                                  id_client]['cipher'])

        msg = {"type": "client-disconnect", "src": self.id,
               "dst": id_client,
               "data": {'flag': flag, 'cif': msg_cifrar, 'salt-cifra': salt_cifra, 'salt-hash': salt_hash,
                        'IV': IV_sending, 'phase': 1}}

        msg = json.dumps(msg)

        # mensagem cifrada

        IV_sending2, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                            self.cipher)

        secure = {"type": "secure",
                  "sa-data": {"IV": IV_sending2, "salt-cifra": salt_cifra, "salt-hash": salt_hash},
                  "payload": {"msg": msg_c}}

        data = json.dumps(secure)
        self.sock.send(data + "\n\n")

    def ServerDisconnect(self):
        '''
        Funçao que trata da primeira mensagem a ser enviada quando o cliente se quer disconectar do servidor

        Vai por o valor 1 na função: self.ClientDisconnect(id_client, flag) para que os clientes ligados a estes saibam que este cliente
        vai acabar a ligação com o servidor e assim o possam retirar dos clientes ligados a si.

        :return:
        '''

        for k, v in self.clients_on.iteritems():
            logging.warning('Disconnected from client ' + v['name'])
            self.ClientDisconnect(k, 1)

        msg = {"type": "disconnect", "src": self.id,
               "data": {}}

        msg = json.dumps(msg)

        IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                           self.cipher)

        secure = {"type": "secure",
                  "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra, "salt-hash": salt_hash},
                  "payload": {"msg": msg_c}}

        data = json.dumps(secure)
        self.sock.send(data + "\n\n")
        return

    def ClientHandshake(self, id, cipher):
        '''
        Função que trata de enviar a primeira mensagem para o servidor a dizer que queremos fazer um handshake com outro cliente.

        Enviamos a cifra que pretendemos usar, para que o servidor verifique se o cliente suporta a mesma


        :param id: id do cliente a que nos queremos ligar
        :param cipher: cipher pretendida; escolhida manualmente pelo utilizador
        :return:
        '''

        if cipher == '1':
            cip = ['ECDHE-AES128-SHA']
        elif cipher == '2':
            cip = ['ECDHE-AES256-SHA']
        elif cipher == '3':
            cip = client.cipherspec
        else:
            logging.warning("Invalid Option on the cipher to be used on Client-Client connection")
            self.DisplayOptions()
            return

        # o que queremos pedir
        msg = {"type": "client-connect", "src": self.id, "dst": id,
               "phase": 1, "ciphers": cip, "data": {}}
        msg = json.dumps(msg)

        # mensagem cifrada
        IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                           self.cipher)

        secure = {"type": "secure",
                  "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra, "salt-hash": salt_hash},
                  "payload": {"msg": msg_c}}

        data = json.dumps(secure)
        self.sock.send(data + TERMINATOR)

    def GetList(self):
        '''
        Função que envia uma mensage do tipo "list" para o utilizador, de forma a receber informação sobre todos
        os clientes conectados ao servidor

        :return:
        '''

        # o que queremos pedir
        msg = {"type": "list"}
        msg = json.dumps(msg)

        # mensagem cifrada

        IV_sending, msg_c, salt_cifra, salt_hash = self.GenerateCipherParameters(self.shared_key, msg,
                                                                                           self.cipher)

        secure = {"type": "secure",
                  "sa-data": {"IV": IV_sending, "salt-cifra": salt_cifra, "salt-hash": salt_hash},
                  "payload": {"msg": msg_c}}

        data = json.dumps(secure)
        self.sock.send(data + TERMINATOR)

    def GenerateCipherParameters(self, secret, msg_before, cipher):
        '''
            Função para gerar os parametros que servem para garantir a integridade.

            Geração de o IV usado(tem de ser diferente a cada msg)
            Geração de um HASH/HMAC da mensagem antes de ser cifrada
            Geração da mensagem cifrada
            Geração do salt a ser usado para criar a chave derivada para cifrar a mensagem
            Geração do salt a ser usado para criar o HASH/HMAC

        :param secret: segredo acordado entre os dois endereços
        :param msg_before: mensagem para ser cifrada
        :param cipher:  cifra a ser usada
        :return:
        '''

        my_salt_cifra = os.urandom(16)
        my_salt_hmac = os.urandom(16)
        iv = utilsAES.generateIV()
        chave_derivada_cifra = utilsAES.derivate(secret, my_salt_cifra, cipher)
        chave_derivada_hmac = utilsAES.derivate(secret, my_salt_hmac, cipher)
        request_cifrado = utilsAES.encryptAES(chave_derivada_cifra, msg_before, iv)
        hash_msg_cif = utilsAES.generateHashMsg(chave_derivada_hmac, request_cifrado)

        return base64.b64encode(iv), base64.b64encode(request_cifrado + hash_msg_cif) ,base64.b64encode(my_salt_cifra), base64.b64encode(my_salt_hmac)

    def DecipherMessage(self, iv, msg, salt_cifra, salt_hmac, secret, cipher):
        '''
        Função para decifrar a mensagem e verificar um HASH/HMAC a partir da mensagem cifrada


        :param iv: IV utilizado a fazer a encriptação, e por isso necessário para a decriptação
        :param msg: Mensagem cifrada enviada e que tem de ser decifrada
        :param salt_cifra: Salt usado para criar a chave derivada usada a cifrar
        :param salt_hmac: Salt usado para gerar o HASH/HMAC da mensagem original
        :param secret: Segredo acordado entre o src e dst
        :param cipher: Cifra usada e acordada entre o src e dst
        :return:
        '''

        chave_derivada_cifra = utilsAES.derivate(secret, salt_cifra, cipher)
        chave_derivada_hmac = utilsAES.derivate(secret, salt_hmac, cipher)
        try:
            hash_verify = utilsAES.VerifyHashMsg(chave_derivada_hmac, msg[:-32], msg[-32:])
        except:
            logging.error('A mensagem foi adulterada')
            return 'ERRO', ''
        msg_decifrada = utilsAES.decryptAES(chave_derivada_cifra, msg[:-32], iv)
        return 'OK', msg_decifrada


if __name__ == "__main__":

    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                        formatter=logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s'))

    client = None
    while True:
        try:
            logging.info("Starting Secure IM Server v1.0")

            name = raw_input("Indique o nome do cliente:\n\n--->")

            num = 0
            out = False
            while out == False:
                num = raw_input("\n\nIndique a cipherspect que quer utilizar:\n"
                                "[1]'ECDHE-AES128-SHA'\n"
                                "[2]'ECDHE-AES256-SHA'\n"
                                "[3] Enviar ambos e o servidor escolher\n\n--->")

                if num in ['1', '2', '3']:
                    out = True

            if num == '1':
                cip = ['ECDHE-AES128-SHA']
            elif num == '2':
                cip = ['ECDHE-AES256-SHA']
            else:
                cip = ['ECDHE-AES128-SHA', 'ECDHE-AES256-SHA']

            client = Client(name, cip)

            msg = {'name': client.name, 'type': 'connect', 'phase': 1, 'ciphers': client.cipherspec, 'id': client.id,
                   'data': {}}

            data = json.dumps(msg)
            client.sock.send(data + TERMINATOR)

            client.loop()
        except KeyboardInterrupt:
            client.stop()
            try:
                logging.info("Press CTRL-C again within 2 sec to quit")
                time.sleep(2)
            except KeyboardInterrupt:
                logging.info("CTRL-C pressed twice: Quitting!")
                break
        except:
            logging.exception("Server Error")
            sys.exit(0)
