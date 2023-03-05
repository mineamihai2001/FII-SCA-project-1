import socket
from dotenv import dotenv_values

config = dotenv_values("../.env")

HOST = config["HOST"]
PORT = int(str(config["PORT"]))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    s.sendall(b"Hello, world")
    data = s.recv(1024)

print(f"Received {data!r}")
