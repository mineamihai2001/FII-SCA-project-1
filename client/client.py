import select
import socket
import time
import CLI
import web_segment
import json
from binascii import hexlify
from dotenv import dotenv_values

config = dotenv_values("../.env")

HOST = config["HOST"]
PORT = str(config["PORT"])

TIMEOUT = 2


class Client:
    host: str
    port: int
    sock: socket.socket

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def connect(self) -> None:
        try:
            self.sock.connect((self.host, self.port))
        except BaseException as e:
            print(f"[ERROR] - connect error - {e}")
        self.comm_loop()

    def comm_loop(self) -> None:
        # request shop available items
        message = CLI.main_menu()
        self.send(message)
        shop_data = self.receive()

        # submit a purchase
        amount = CLI.products_menu(shop_data)
        self.send(amount)
        # recieves the payment Web segment with the digital certificates
        response = self.receive()
        print("Received: ", response)

        webSegment = web_segment.WebSegment(amount)
        # step 1
        step1_message = webSegment.step1()
        self.send(step1_message)

        # step 2
        step2_msg = self.receive()
        try:
            if webSegment.step2(json.loads(step2_msg)):
                print(f"[DEBUG] M authenticated")
        except BaseException as e:
            print(f"[ERROR] - M can't be authenticated - {e}")

        # step 3
        step3_msg = webSegment.step3()
        self.send(step3_msg)

        # step 6
        step6_msg = self.receive()
        if step6_msg == "timeout":
            print("[WARNING] Timeout exceeded. Trying to retrieve transaction")
            step7_msg = webSegment.step7()
            self.send(step7_msg)
            transaction_msg = self.receive()
            # decrypt transaction_msg
            Resp, verified = webSegment.step8(json.loads(transaction_msg))
            isVerified = "verified" if verified == True else "unverified"
            if Resp == True:
                print("[SERVER - INFO] - payment successful and ", isVerified)
            else:
                print("[SERVER - INFO] - payment error")
        else:
            Resp, verified = webSegment.step6(json.loads(step6_msg))
            isVerified = "verified" if verified == True else "unverified"
            if Resp == True:
                print("[SERVER - INFO] - payment successful and ", isVerified)
            else:
                print("[SERVER - INFO] - payment error")


    def send(self, message: str):
        message_buffer = str.encode(message)
        message_length = len(message_buffer).to_bytes(2, 'big')
        buffer = message_length + message_buffer

        self.sock.sendall(buffer)

    def receive(self) -> str:
        header = self.sock.recv(2)
        message_length = int.from_bytes(header, "big")

        buffer = self.sock.recv(message_length)
        data = buffer.decode("utf-8")
        # print(f"[DEBUG] received -> {data}")
        return data

    def receive_non_blocking(self) -> str:
        self.sock.setblocking(0)
        try:
            ready = select.select([self.sock], [], [], TIMEOUT)
            if (ready[0]):
                header = self.sock.recv(2)
                message_length = int.from_bytes(header, "big")

                buffer = self.sock.recv(message_length)
                data = buffer.decode("utf-8")
                print(f"[DEBUG] received -> {data}")
                return data
        except BaseException as e:
            return None


def main():
    client = Client(str(HOST), int(PORT))
    client.connect()


if __name__ == "__main__":
    main()
