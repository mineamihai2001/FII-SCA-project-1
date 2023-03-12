import socket
from dotenv import dotenv_values
from typing import Callable, Any

config = dotenv_values("../.env")

HOST = config["HOST"]
PORT = str(config["PORT"])


class Server:
    host: str
    port: int
    sock: socket.socket
    conn: socket.socket

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

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
                msg = self.receive()
                self.send("Hello there")

    def receive(self) -> str:
        header = self.conn.recv(2)
        message_length = int.from_bytes(header, "big")
        buffer = self.conn.recv(message_length)
        data = buffer.decode("utf-8")
        return data

    def send(self, message: str):
        try:
            message_buffer = str.encode(message)
            message_length = len(message_buffer).to_bytes(2, 'big')
            buffer = message_length + message_buffer

            self.conn.sendall(buffer)
        except BaseException as e:
            print(f"[ERROR] - send error {e}")


def main():
    server = Server(str(HOST), int(PORT))
    server.run(lambda: print(f"server running on port {PORT}"))


if __name__ == "__main__":
    main()
