import socket
from dotenv import dotenv_values

config = dotenv_values("../.env")

HOST = config["HOST"]
PORT = int(str(config["PORT"]))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print(f"Server listening on {HOST}:{PORT}")
    conn, addr = s.accept()
    with conn:
        print(f"Client {addr} connected")
        while True:
            data = conn.recv(1024)
            if not data:
                break
            conn.sendall(data)
