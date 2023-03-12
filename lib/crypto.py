import rsa
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


def generate_rsa_keys(out_dir: str):
    public_key, private_key = rsa.newkeys(1024)
    with open(f"{out_dir}/public_key.pem", "wb+") as f:
        f.write(public_key.save_pkcs1("PEM"))
    with open(f"{out_dir}/private_key.pem", "wb+") as f:
        f.write(private_key.save_pkcs1("PEM"))


def load_rsa_keys(source: str):
    with open(f"{source}/public_key.pem", 'rb') as p:
        public_key = rsa.PublicKey.load_pkcs1(p.read())
    with open(f"{source}/private_key.pem", 'rb') as p:
        private_key = rsa.PrivateKey.load_pkcs1(p.read())
    return private_key, public_key


def encrypt_rsa(message: str, key):
    return rsa.encrypt(message.encode('ascii'), key)


def decrypt_rsa(cipher_text: bytes, key):
    try:
        return rsa.decrypt(cipher_text, key).decode('ascii')
    except:
        return False


def sign_rsa(message: str, key):
    return rsa.sign(message.encode('ascii'), key, 'SHA-1')


def verify(message: str, signature: bytes, key):
    try:
        return rsa.verify(message.encode('ascii'), signature, key,) == 'SHA-1'
    except:
        return False


def generate_aes_key(out_dir: str | None = None):
    key = get_random_bytes(16)
    if out_dir == None:
        return key
    with open(f"{out_dir}/aes_key.pem", "wb+") as f:
        f.write(key)
    return key


def encrypt_aes(data: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_EAX)
    cipher_text, tag = cipher.encrypt_and_digest(data)
    nonce = cipher.nonce
    return cipher_text, nonce, tag


def decrypt_aes(cipher_text: bytes, nonce: bytes, tag: bytes, key: bytes):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(cipher_text, tag)
    return data


if __name__ == "__main__":
    generate_rsa_keys("../server/certs")
    private_key, public_key = load_rsa_keys("../server/certs")
    message = "Hello there"
    cipher_text = encrypt_rsa(message, public_key)

    signature = sign_rsa(message, private_key)
    text = decrypt_rsa(cipher_text, private_key)

    print(">> [RSA] - ", cipher_text)
    print(">> [RSA] - ", signature)
    print(">> [RSA] - ", text)

    #### AES ####
    key = generate_aes_key("../server/certs")
    cipher_text, nonce, tag = encrypt_aes(b"testing123", key)
    print(">> [AES] - ", cipher_text)
    print(">> [AES] -", decrypt_aes(cipher_text, nonce, tag, key))
