import socket
import threading

from encryption import AES  # Assuming AES class is in a separate file

clients = {}


def handle_client(client_socket, client_address):
    try:
        # Receive AES key from client (in production, secure key exchange like RSA should be used)
        aes_key = client_socket.recv(32)
        aes = AES(aes_key)

        while True:
            encrypted_message = client_socket.recv(1024)
            if encrypted_message:
                decrypted_message = aes.decrypt(encrypted_message).decode('utf-8')
                print(f"Client {client_address}: {decrypted_message}")

                # Echo message back to client (or broadcast to other clients if needed)
                response_message = f"Received: {decrypted_message}"
                encrypted_response = aes.encrypt(response_message.encode('utf-8'))
                client_socket.send(encrypted_response)
            else:
                print(f"Client {client_address} disconnected.")
                break
    except Exception as e:
        print(f"Error handling client {client_address}: {e}")
    finally:
        client_socket.close()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('0.0.0.0', 9999))
    server_socket.listen(5)
    print("Server listening on port 9999...")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Accepted connection from {client_address}")

        client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address))
        client_thread.start()


if __name__ == "__main__":
    main()
