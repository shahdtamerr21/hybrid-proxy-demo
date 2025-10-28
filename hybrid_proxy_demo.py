import socket
import threading
import time
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    return public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )

def rsa_decrypt(private_key, ciphertext):
    return private_key.decrypt(
        ciphertext,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    ).decode()

def encrypt_message(message, mode, public_key):
    if mode == "RSA":
        return rsa_encrypt(public_key, message)
    else:
        return f"PQC({message})".encode()  # simulated PQC encryption

def decrypt_message(ciphertext, mode, private_key):
    if mode == "RSA":
        return rsa_decrypt(private_key, ciphertext)
    else:
        return ciphertext.decode().replace("PQC(", "").replace(")", "")

def server():
    private_key, public_key = generate_rsa_keys()

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(("localhost", 5555))
    server_socket.listen(1)
    print("[SERVER] Listening on port 5555...")

    global SERVER_PUBLIC_KEY
    SERVER_PUBLIC_KEY = public_key

    while True:
        conn, addr = server_socket.accept()
        print(f"[SERVER] Connection from {addr}")

        data = conn.recv(4096)
        if not data:
            continue

        mode, ciphertext = data.split(b"||", 1)
        mode = mode.decode()

        try:
            decrypted_message = decrypt_message(ciphertext, mode, private_key)
            print(f"[SERVER] Received ({mode}): {decrypted_message}")
            conn.sendall("Message received and decrypted successfully.".encode())
        except Exception as e:
            print(f"[SERVER] Decryption error: {e}")
            conn.sendall("Decryption failed.".encode())

        conn.close()

def client(message, mode="RSA"):
    time.sleep(0.5)
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(("localhost", 5555))

    ciphertext = encrypt_message(message, mode, SERVER_PUBLIC_KEY)
    client_socket.sendall(f"{mode}||".encode() + ciphertext)

    response = client_socket.recv(1024)
    print(f"[CLIENT] Server response: {response.decode()}")
    client_socket.close()

if __name__ == "__main__":
    threading.Thread(target=server, daemon=True).start()
    time.sleep(1)

    client("Hello from Client using RSA", mode="RSA")
    client("Hello from Client using PQC", mode="PQC")

    time.sleep(1)
    print("\n Demo finished successfully.")
