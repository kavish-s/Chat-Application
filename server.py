import socket
import threading
import tkinter as tk
from tkinter import scrolledtext

from encryption import AES  # Assuming AES class is in a separate file

clients = []  # List to keep track of connected clients


class ServerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Chat Server")
        self.root.geometry("500x600")

        self.chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=20)
        self.chat_area.pack(pady=10, padx=10)

        self.debug_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=10)
        self.debug_area.pack(pady=10, padx=10)

        self.start_button = tk.Button(root, text="Start Server", command=self.start_server)
        self.start_button.pack(pady=5)

        self.debug_mode = tk.BooleanVar(value=False)
        self.debug_checkbox = tk.Checkbutton(root, text="Debug Mode", variable=self.debug_mode)
        self.debug_checkbox.pack(pady=5)

    def start_server(self):
        threading.Thread(target=self.run_server, daemon=True).start()

    def run_server(self):
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.bind(('127.0.0.1', 9999))
        server_socket.listen(5)
        self.log_message("Server listening on port 9999...")

        while True:
            client_socket, address = server_socket.accept()
            threading.Thread(target=self.handle_client, args=(client_socket, address), daemon=True).start()

    def handle_client(self, client_socket, address):
        try:
            self.log_message(f"Accepted connection from {address}")

            # Step 1: Receive AES key from the client
            aes_key = client_socket.recv(32)  # Expecting a 32-byte AES key
            aes = AES(aes_key)  # Initialize AES encryption with the received key

            # Step 2: Receive the alias
            alias = client_socket.recv(1024).decode('utf-8')
            self.log_message(f"{alias} has joined the chat from {address}")
            clients.append((client_socket, aes, alias))

            # Step 3: Handle receiving messages from the client
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
    app = ServerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
