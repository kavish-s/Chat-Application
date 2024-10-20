import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

from encryption import AES

# List of connected clients, each represented by (socket, AES object, alias)
clients = []


# Server GUI class to manage the chat server's interface and operations
class ServerGUI:
    def __init__(self, root):
        # Initialize the main window with title and size
        self.root = root
        self.root.title("Chat Server")
        self.root.geometry("500x650")

        # Chat area to display messages
        self.chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=20)
        self.chat_area.pack(pady=10, padx=10)

        # Debug area to display technical logs
        self.debug_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=10)
        self.debug_area.pack(pady=10, padx=10)

        # Buttons for starting and closing the server
        self.start_button = tk.Button(root, text="Start Server", command=self.start_server)
        self.start_button.pack(pady=5)
        self.close_button = tk.Button(root, text="Close Server", command=self.close_server, state='disabled')
        self.close_button.pack(pady=5)

        # Checkbox to enable or disable debug mode
        self.debug_mode = tk.BooleanVar(value=False)
        self.debug_checkbox = tk.Checkbutton(root, text="Debug Mode", variable=self.debug_mode)
        self.debug_checkbox.pack(pady=5)

        # Generate RSA private key for the server (used to decrypt AES keys from clients)
        self.rsa_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Extract the corresponding RSA public key
        self.rsa_public_key = self.rsa_private_key.public_key()

        self.server_thread = None  # Placeholder for the server thread

    def start_server(self):
        # Start the server thread if it's not already running
        if not self.server_thread or not self.server_thread.is_alive():
            self.server_thread = threading.Thread(target=self.run_server, daemon=True)
            self.server_thread.start()

            # Enable/disable relevant buttons when server starts
            self.close_button.config(state='normal')
            self.start_button.config(state='disabled')

    def run_server(self):
        # Create a TCP socket, bind it to localhost, and listen for connections
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('127.0.0.1', 9999))  # Server runs on port 9999
        server_socket.listen(5)  # Can accept 5 connections in the queue

        # Log the server start message
        self.log_message("Server listening on port 9999...")

        # Continuously accept client connections
        while True:
            client_socket, address = server_socket.accept()  # Wait for a client to connect
            self.log_message(f"Accepted connection from {address}")

            # Handle the client connection in a new thread
            threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()

    def handle_client(self, client_socket, address):
        try:
            # Step 1: Send RSA public key to the client
            public_key_bytes = self.rsa_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            client_socket.send(public_key_bytes)

            # Step 2: Receive encrypted AES key from client and decrypt it using RSA private key
            encrypted_aes_key = client_socket.recv(256)
            aes_key = self.rsa_private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            aes = AES(aes_key)  # Initialize AES object for this client
            self.log_debug(f"Received and decrypted AES key from {address}")

            # Step 3: Receive client's alias and store the client info
            alias = client_socket.recv(1024).decode('utf-8')
            self.log_message(f"{alias} has joined the chat from {address}")
            clients.append((client_socket, aes, alias))  # Add client to the list

            # Receive and broadcast messages from the client
            while True:
                encrypted_message = client_socket.recv(1024)
                if encrypted_message:
                    # Decrypt the message using the client's AES key
                    decrypted_message = aes.decrypt(encrypted_message).decode('utf-8')
                    self.broadcast_message(decrypted_message, client_socket)
                    self.log_debug(f"Received encrypted message: {encrypted_message.hex()}")
                    self.log_debug(f"Decrypted message: {decrypted_message}")
                else:
                    self.log_message(f"{alias} has left the chat.")
                    break

        except Exception as e:
            # Log errors if something goes wrong with the client
            self.log_message(f"Error handling client {address}: {e}")
        finally:
            # Close the connection when the client disconnects
            client_socket.close()

    def broadcast_message(self, message, sending_socket):
        # Send the message to all clients except the one who sent it
        for client_socket, aes, alias in clients:
            if client_socket != sending_socket:
                try:
                    # Encrypt the message with the recipient's AES key
                    encrypted_message = aes.encrypt(message.encode('utf-8'))
                    client_socket.send(encrypted_message)  # Send the encrypted message
                    self.log_debug(f"Sent encrypted message to {alias}: {encrypted_message.hex()}")
                except Exception as e:
                    self.log_message(f"Error sending message to {alias}: {e}")

    def close_server(self):
        # Close all client connections and clear the client list
        for client_socket, _, _ in clients:
            client_socket.close()
        clients.clear()

        # Log server closure and reset button states
        self.log_message("Server closed.")
        self.start_button.config(state='normal')
        self.close_button.config(state='disabled')

    def log_message(self, message):
        # Log a message in the chat area
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + '\n')
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def log_debug(self, message):
        # Log debug messages if debug mode is enabled
        if self.debug_mode.get():
            self.debug_area.config(state='normal')
            self.debug_area.insert(tk.END, message + '\n')
            self.debug_area.config(state='disabled')
            self.debug_area.yview(tk.END)


# Main function to run the server GUI
def main():
    root = tk.Tk()  # Create the root Tkinter window
    ServerGUI(root)  # Initialize the Server GUI
    root.mainloop()  # Start the Tkinter main loop


if __name__ == "__main__":
    main()
