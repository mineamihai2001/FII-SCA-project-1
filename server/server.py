import select
import time
from PG import PG
import socket
from dotenv import dotenv_values
from typing import Callable, Any
import utils
import json
import random
from binascii import hexlify
import sys
import rsa
from lib import crypto
# import crypto
# sys.path.insert(0, "C:\\Users\\Laura\\Desktop\\SCA-project-1\\lib")
# sys.path.insert(0, "C:\\Users\\Laura\\Desktop\\SCA-project-1\\server\\PG")

config = dotenv_values("../.env")

HOST = config["HOST"]
PORT = str(config["PORT"])


class Server:
    host: str
    port: int
    sock: socket.socket
    conn: socket.socket
    PrivKM: any
    PubKM: any
    K: any
    PubKC: any
    PO: any

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def run(self, callback: Callable[[], None]) -> None:
        callback()
        try:
            self.sock.bind((self.host, self.port))
            self.sock.listen()
        except BaseException as e:
            print("[ERROR] - connection error", e)
            return
        self.comm_loop()

    def comm_loop(self):
        while True:
            conn, addr = self.sock.accept()
            self.conn = conn
            with conn:
                print(f"Client {addr} connected")
                # receive shop request
                msg = self.receive()
                self.send(json.dumps(utils.get_shop_items()))

                # receive purchase submit
                msg = self.receive()

                # download of the payment Web segment
                # has the digital certificates for the public keys of M/PG

                # rsa keys for M
                self.PrivKM, self.PubKM = crypto.load_rsa_keys("../server/certs")
                # rsa keys for PG
                crypto.generate_rsa_keys("../server/PG/certs")
                self.PrivKPG, self.PubKPG = crypto.load_rsa_keys("../server/PG/certs")
                pg = PG.PaymentGateway(self.PubKPG, self.PrivKPG, self.PubKM)

                # generate session AES key (not sure)
                self.K = crypto.generate_aes_key("../server/certs")
                self.send("web_segment")

                # step 1
                step1_response = self.receive()  # receive {PubKC} from C
                self.PubKC = self.step1(json.loads(step1_response))  # get PubKC

                # step 2
                self.send(self.step2())  # send {Sid, SigM(Sid)}

                # step 3
                step3_msg = self.receive()
                PM = self.step3(json.loads(step3_msg))

                # step 4
                step4_msg = self.step4(PM)
                step5_msg = pg.step4(step4_msg, json.loads(step1_response)["nonce"])

                # step 5
                start = time.time()
                step6_msg = self.step5(json.loads(step5_msg))
                time.sleep(5)  # PG TIMEOUT
                end = time.time()

                if end-start < 3:
                    self.send(step6_msg)
                else:
                    print("timeout exceeded")
                    self.send("timeout")
                    step7_msg = self.receive()
                    msg = pg.step8(self.PubKC, json.loads(step7_msg))
                    self.send(msg)

    def receive(self) -> str:
        header = self.conn.recv(2)
        message_length = int.from_bytes(header, "big")
        buffer = self.conn.recv(message_length)
        data = buffer.decode("utf-8")
        return data

    def receive_non_blocking(self) -> str:
        self.sock.setblocking(0)
        try:
            ready = select.select([self.sock], [], [], 2)
            if (ready[0]):
                header = self.sock.recv(2)
                message_length = int.from_bytes(header, "big")

                buffer = self.sock.recv(message_length)
                data = buffer.decode("utf-8")
                # print(f">>>[DEBUG] received -> {data}")
                return data
        except BaseException as e:
            return None

    def send(self, message: str):
        try:
            message_buffer = str.encode(message)
            message_length = len(message_buffer).to_bytes(2, 'big')
            buffer = message_length + message_buffer

            self.conn.sendall(buffer)
        except BaseException as e:
            print(f"[ERROR] - send error {e}")

    def step1(self, data):
        K = crypto.rsa_decrypt(bytes.fromhex(data['K_PubKM']), self.PrivKM)
        PubKC_bytes = crypto.aes_decrypt(bytes.fromhex(data['PubKC_K']),
                                         bytes.fromhex(data['nonce']),
                                         bytes.fromhex(data['tag']),
                                         bytes.fromhex(K))
        return rsa.PublicKey.load_pkcs1(PubKC_bytes)

    def step2(self):
        # generate Sid
        Sid = random.randrange(1000, 9999)
        # sign Sid
        Sig_M = crypto.rsa_sign(str(Sid), self.PrivKM)
        msg = {'Sid': str(Sid), 'Sig_M': hexlify(Sig_M).decode('utf-8')}
        # encrypt message
        msg_K, nonce, tag = crypto.aes_encrypt(json.dumps(msg).encode('utf-8'), self.K)
        K_PubKC = crypto.rsa_encrypt(hexlify(self.K).decode('utf-8'), self.PubKC)
        coded_msg = {'msg_K': hexlify(msg_K).decode('utf-8'),
                     'nonce': hexlify(nonce).decode('utf-8'),
                     'tag': hexlify(tag).decode('utf-8'),
                     'K_PubKC': hexlify(K_PubKC).decode('utf-8')}
        return json.dumps(coded_msg)

    def step3(self, data):
        # decrypt received message -> {PM, PO}
        K = crypto.rsa_decrypt(bytes.fromhex(data['K_PubKM']), self.PrivKM)
        msg_bytes = crypto.aes_decrypt(bytes.fromhex(data['msg_K']),
                                       bytes.fromhex(data['nonce']),
                                       bytes.fromhex(data['tag']),
                                       bytes.fromhex(K))
        msg = json.loads(msg_bytes.decode('utf-8'))
        PO = json.loads(msg['PO'])
        PM = msg['PM']

        # verify C's purchase order
        purchase_order = PO['purchase_order']
        SigC_PO = PO['SigC_PO']
        try:
            if crypto.rsa_verify(purchase_order,
                                 bytes.fromhex(SigC_PO),
                                 self.PubKC):
                self.PO = PO
                return PM
        except BaseException as e:
            print(f"[ERROR] - M does not agree to C's PO - {e}")

    def step4(self, PM):
        # create step 4 message -> {PM, SigM(Sid, PubKC, Amount)}
        po_info = json.loads(self.PO['purchase_order'])
        msg = json.dumps({
            'Sid': po_info['Sid'],
            'PubKC': hexlify(self.PubKC.save_pkcs1()).decode('utf-8'),
            'Amount': po_info['Amount']
        })
        SigM_PO = crypto.rsa_sign(msg, self.PrivKM)
        step4_msg = json.dumps({
            'PM': PM,
            'SigM_PO': hexlify(SigM_PO).decode('utf-8')
        })

        # encrypt step 4 message
        msg_K, nonce, tag = crypto.aes_encrypt(json.dumps(step4_msg).encode('utf-8'), self.K)
        K_PubKPG = crypto.rsa_encrypt(hexlify(self.K).decode('utf-8'), self.PubKPG)
        coded_msg = {'msg_K': hexlify(msg_K).decode('utf-8'),
                     'nonce': hexlify(nonce).decode('utf-8'),
                     'tag': hexlify(tag).decode('utf-8'),
                     'K_PubKC': hexlify(K_PubKPG).decode('utf-8')}  # K_PubKPG
        return json.dumps(coded_msg)

    def step5(self, data: dict):
        K = crypto.rsa_decrypt(bytes.fromhex(data["K_PubKM"]), self.PrivKM)
        msg_bytes = crypto.aes_decrypt(bytes.fromhex(data["msg_K"]),
                                       bytes.fromhex(data["nonce"]),
                                       bytes.fromhex(data["tag"]),
                                       bytes.fromhex(K))

        msg = json.loads(msg_bytes.decode("utf-8"))
        step6_msg = msg

        # encrypt step 6 message (same message but needs to be encrypted with the clients Public Key)
        msg_K, nonce, tag = crypto.aes_encrypt(json.dumps(step6_msg).encode('utf-8'), self.K)
        K_PubKC = crypto.rsa_encrypt(hexlify(self.K).decode("utf-8"), self.PubKC)

        coded_msg = {
            "msg_K": hexlify(msg_K).decode("utf-8"),
            "nonce": hexlify(nonce).decode("utf-8"),
            "tag": hexlify(tag).decode("utf-8"),
            "K_PubKC": hexlify(K_PubKC).decode("utf-8"),
        }
        return json.dumps(coded_msg)


def main():
    server = Server(str(HOST), int(PORT))
    server.run(lambda: print(f"server running on port {PORT}"))


if __name__ == "__main__":
    main()
