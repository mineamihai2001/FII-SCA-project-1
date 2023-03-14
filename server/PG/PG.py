import json
from lib import crypto
from binascii import hexlify


class PaymentGateway:
    PubKPG: any
    PrivKPG: any
    K: str
    PubKM: str
    PubKC: str

    def __init__(self, PubKPG, PrivKPG, PubKM) -> None:
        self.PubKPG = PubKPG
        self.PrivKPG = PrivKPG
        self.K = crypto.generate_aes_key("../server/certs")
        self.PubKM = PubKM

    def get_account(self, card_number: str) -> dict | None:
        with open("PG/accounts.json", "r") as f:
            data = json.loads(f.read())
        return data[card_number] if card_number in data else None

    def update_account(self, account: dict, card_number: str, Amount: float):
        with open("PG/accounts.json", "r") as f:
            data = json.loads(f.read())

        account["Balance"] = float(account["Balance"]) - Amount
        data[card_number] = account
        data["777"]["Balance"] = float(data["777"]["Balance"]) + Amount

        with open("PG/accounts.json", "w") as f:
            f.write(json.dumps(data))

    def add_transaction(self, transaction):
        data = list()
        with open("PG/transactions.json", "r+") as f:
            try:
                data: list[dict] = json.loads(f.read())
            except:
                pass
        with open("PG/transactions.json", "w") as f:
            data.append(transaction)
            f.write(json.dumps(data))

    def retrieve_transaction(self, Amount: float, NC: str, Sid: str):
        transaction = {
            "Amount": Amount,
            "NC": NC,
            "Sid": Sid
        }
        print("@@", transaction)
        with open("PG/transactions.json") as f:
            data: list[dict] = json.loads(f.read())
        for t in data:
            if t["Sid"] == transaction["Sid"] and t["Amount"] == transaction["Amount"] and t["NC"] == transaction["NC"]:
                return t
        return None

    def step4(self, message, NC) -> bool:
        message = json.loads(message)

        cipher_text = message["msg_K"]
        enc_key = message["K_PubKC"]
        dec_key = crypto.rsa_decrypt(bytes.fromhex(enc_key), self.PrivKPG)
        plain_text = crypto.aes_decrypt(bytes.fromhex(cipher_text), bytes.fromhex(message["nonce"]), bytes.fromhex(message["tag"]), bytes.fromhex(dec_key))
        decrypted = json.loads(json.loads(plain_text))

        PM = json.loads(decrypted["PM"])
        SigM_PO = decrypted["SigM_PO"]

        cipher_text = PM["PM_K"]
        enc_key = PM["K_PubKPG"]

        dec_key = crypto.rsa_decrypt(bytes.fromhex(enc_key), self.PrivKPG)

        dec_msg = crypto.aes_decrypt(bytes.fromhex(cipher_text), bytes.fromhex(PM["nonce"]), bytes.fromhex(PM["tag"]), bytes.fromhex(dec_key))
        dec_msg = json.loads(dec_msg)

        PI = json.loads(dec_msg["PI"])

        Resp: bool = True
        account = self.get_account(PI["CardN"])
        if account == None or account["CCode"] != PI["CCode"]:
            print("[ERROR] - account not found!")
            Resp = False
        elif float(account["Balance"]) < float(PI["Amount"]):
            print("[ERROR] - insufficient funds")
            Resp = False
        elif PI["M"] != "idk":  # TODO: check M's signature/identity
            print("[ERROR] - could not verify server's signature", PI)
            Resp = False

        crypto.rsa_verify(PM["PM_K"], SigM_PO, self.PubKM)

        # PG sends the PM to the bank
        if Resp == True:
            self.update_account(account, PI["CardN"], float(PI["Amount"]))
            transaction = {
                "Resp": Resp,
                "Sid": PI["Sid"],
                "Amount": PI["Amount"],
                "NC": PI["NC"],
            }
            print("adding transaction ...", transaction)
            self.add_transaction(transaction)
        return self.step5(Resp, PI["Sid"], float(PI["Amount"]), NC)

    def step5(self, Resp: bool, Sid: str, Amount: float, NC: str):
        msg = json.dumps({
            "Amount": Amount,
            "NC": NC
        })

        Sig_PM = crypto.rsa_sign(msg, self.PrivKPG)
        step5_msg = json.dumps({
            "Resp": Resp,
            "Sid": Sid,
            "Sig_PM": hexlify(Sig_PM).decode("utf-8")
        })

        # encrypt step 5 message
        msg_K, nonce, tag = crypto.aes_encrypt(json.dumps(step5_msg).encode('utf-8'), self.K)
        K_PubKM = crypto.rsa_encrypt(hexlify(self.K).decode("utf-8"), self.PubKM)

        coded_msg = {
            "msg_K": hexlify(msg_K).decode("utf-8"),
            "nonce": hexlify(nonce).decode("utf-8"),
            "tag": hexlify(tag).decode("utf-8"),
            "K_PubKM": hexlify(K_PubKM).decode("utf-8"),
        }
        return json.dumps(coded_msg)

    def step8(self, PubKC: any, data):
        K = crypto.rsa_decrypt(bytes.fromhex(data["K_PubKPG"]), self.PrivKPG)
        msg_bytes = crypto.aes_decrypt(bytes.fromhex(data["msg_K"]),
                                       bytes.fromhex(data["nonce"]),
                                       bytes.fromhex(data["tag"]),
                                       bytes.fromhex(K))

        transaction_msg: dict = json.loads(msg_bytes.decode("utf-8"))

        transaction = self.retrieve_transaction(transaction_msg["Amount"], transaction_msg["NC"], transaction_msg["Sid"])
        print("transaction found ==> ", transaction)

        msg = json.dumps({
            "Amount": transaction_msg["Amount"],
            "NC":  transaction_msg["NC"],
            "Resp": transaction["Resp"],
            "Sid":  transaction_msg["Sid"],
        })

        Sig_PG = crypto.rsa_sign(msg, self.PrivKPG)
        step8_msg: str = json.dumps({
            "Resp": transaction["Resp"],
            "Sid":  transaction_msg["Sid"],
            "Sig_PG": hexlify(Sig_PG).decode("utf-8")
        })

        # encrypt step 5 message
        msg_K, nonce, tag = crypto.aes_encrypt(json.dumps(step8_msg).encode('utf-8'), self.K)
        K_PubKC = crypto.rsa_encrypt(hexlify(self.K).decode("utf-8"), PubKC)

        coded_msg = {
            "msg_K": hexlify(msg_K).decode("utf-8"),
            "nonce": hexlify(nonce).decode("utf-8"),
            "tag": hexlify(tag).decode("utf-8"),
            "K_PubKC": hexlify(K_PubKC).decode("utf-8"),
        }
        return json.dumps(coded_msg)
