import os
import socket
import threading

from encryption import AES  # Assuming AESEncryption class is in a separate file

# AES key should be 32 bytes (256 bits) for AES-256
aes_key = os.urandom(32)
aes = AES(aes_key)


def receive_messages(client_socket):
    while True:
        try:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                decrypted_message = aes.decrypt(encrypted_message).decode('utf-8')
                print(f"Server: {decrypted_message}")
            else:
                print("Server disconnected.")
                break
        except Exception as e:
            print(f"Error receiving message: {e}")
            break


def main():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 9999))  # Connect to server

    # Send AES key to the server (ideally use RSA for secure key exchange in production)
    client_socket.send(aes_key)

    # Start a thread to receive messages from the server
    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.start()

    while True:
        message = input("You: ")
        encrypted_message = aes.encrypt(message.encode('utf-8'))
        client_socket.send(encrypted_message)


if __name__ == "__main__":
    main()
