import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from encryption import AES

clients = []  # List to keep track of connected clients


class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Server")
        self.root.geometry("500x650")

        self.chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=20)
        self.chat_area.pack(pady=10, padx=10)

        self.debug_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=10)
        self.debug_area.pack(pady=10, padx=10)

        self.start_button = tk.Button(root, text="Start Server", command=self.start_server)
        self.start_button.pack(pady=5)

        self.close_button = tk.Button(root, text="Close Server", command=self.close_server, state='disabled')
        self.close_button.pack(pady=5)

        self.debug_mode = tk.BooleanVar(value=False)
        self.debug_checkbox = tk.Checkbutton(root, text="Debug Mode", variable=self.debug_mode)
        self.debug_checkbox.pack(pady=5)

        # Generate RSA key pair
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.rsa_public_key = self.rsa_private_key.public_key()

        self.server_thread = None  # Thread to run the server

    def start_server(self):
        if not self.server_thread or not self.server_thread.is_alive():
            self.server_thread = threading.Thread(target=self.run_server, daemon=True)
            self.server_thread.start()
            self.close_button.config(state='normal')  # Enable the Close Server button
            self.start_button.config(state='disabled')  # Disable Start button

    def run_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('127.0.0.1', 9999))
        server_socket.listen(5)
        self.log_message("Server listening on port 9999...")

        while True:
            client_socket, address = server_socket.accept()
            self.log_message(f"Accepted connection from {address}")
            threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()

    def handle_client(self, client_socket, address):
        try:
            # Send RSA public key to the client
            public_key_bytes = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.send(public_key_bytes)

            # Receive encrypted AES key from the client
            encrypted_aes_key = client_socket.recv(256)
            aes_key = self.rsa_private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            aes = AES(aes_key)
            self.log_debug(f"Received and decrypted AES key from {address}")

            # Handle client communication
            alias = client_socket.recv(1024).decode('utf-8')
            self.log_message(f"{alias} has joined the chat from {address}")
            clients.append((client_socket, aes, alias))

            while True:
                encrypted_message = client_socket.recv(1024)
                if encrypted_message:
                    decrypted_message = aes.decrypt(encrypted_message).decode('utf-8')
                    self.broadcast_message(decrypted_message, client_socket)
                    self.log_debug(f"Received encrypted message: {encrypted_message.hex()}")
                    self.log_debug(f"Decrypted message: {decrypted_message}")
                else:
                    self.log_message(f"{alias} has left the chat.")
                    break

        except Exception as e:
            self.log_message(f"Error handling client {address}: {e}")
        finally:
            client_socket.close()

    def broadcast_message(self, message, sending_socket):
        for client_socket, aes, alias in clients:
            if client_socket != sending_socket:  # Don't send the message back to the sender
                try:
                    encrypted_message = aes.encrypt(message.encode('utf-8'))
                    client_socket.send(encrypted_message)
                    self.log_debug(f"Sent encrypted message to {alias}: {encrypted_message.hex()}")
                except Exception as e:
                    self.log_message(f"Error sending message to {alias}: {e}")

    def close_server(self):
        for client_socket, _, _ in clients:
            client_socket.close()  # Close each client connection
        clients.clear()  # Clear the client list
        self.log_message("Server closed.")
        self.start_button.config(state='normal')  # Re-enable Start Server button
        self.close_button.config(state='disabled')  # Disable Close Server button

    def log_message(self, message):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + '\n')
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def log_debug(self, message):
        if self.debug_mode.get():  # Only log if debug mode is enabled
            self.debug_area.config(state='normal')
            self.debug_area.insert(tk.END, message + '\n')
            self.debug_area.config(state='disabled')
            self.debug_area.yview(tk.END)


# Main function to start the server GUI
def main():
    root = tk.Tk()
    ServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
