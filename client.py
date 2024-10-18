import os
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

from encryption import AES


class ChatGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Chat Application")
        self.root.geometry("400x500")

        self.alias = ""
        self.client_socket = None

        # Set up GUI elements
        self.chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=15)
        self.chat_area.pack(pady=10)

        self.message_entry = tk.Entry(root, width=40)
        self.message_entry.pack(pady=5, padx=10)
        self.message_entry.bind("<Return>", self.send_message)  # Send message on pressing Enter

        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack(pady=5)

        # Add exit button
        self.exit_button = tk.Button(root, text="Exit", command=self.exit_chat)
        self.exit_button.pack(pady=5)

        # Ask for alias on the same canvas
        self.alias_label = tk.Label(root, text="Please enter your alias:")
        self.alias_label.pack(pady=10)

        self.alias_entry = tk.Entry(root)
        self.alias_entry.pack(pady=5)

        self.alias_button = tk.Button(root, text="OK", command=self.set_alias)
        self.alias_button.pack(pady=10)

    def set_alias(self):
        alias = self.alias_entry.get().strip()
        if alias:
            self.alias = alias
            self.alias_label.pack_forget()
            self.alias_entry.pack_forget()
            self.alias_button.pack_forget()
            self.connect_to_server()
        else:
            messagebox.showerror("Error", "Alias cannot be empty!")

    def connect_to_server(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('127.0.0.1', 9999))  # Connect to the server

            # Step 1: Receive server's RSA public key
            rsa_public_key = serialization.load_pem_public_key(self.client_socket.recv(1024), backend=default_backend())

            # Step 2: Generate AES key and encrypt it with server's RSA public key
            aes_key = os.urandom(32)  # 32 bytes for AES-256
            encrypted_aes_key = rsa_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Step 3: Send encrypted AES key to the server
            self.client_socket.send(encrypted_aes_key)

            self.aes = AES(aes_key)  # Initialize AES cipher with the key
            self.client_socket.send(self.alias.encode('utf-8'))

            threading.Thread(target=self.receive_messages, daemon=True).start()

        except Exception as e:
            messagebox.showerror("Error", f"Error connecting to server: {e}")
            self.root.quit()

    def receive_messages(self):
        try:
            while True:
                encrypted_message = self.client_socket.recv(1024)
                if encrypted_message:
                    message = self.aes.decrypt(encrypted_message).decode('utf-8')
                    self.display_message(message)
                else:
                    break
        except Exception as e:
            self.display_message(f"Error receiving message: {e}")

    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if message:
            full_message = f"{self.alias}: {message}"
            encrypted_message = self.aes.encrypt(full_message.encode('utf-8'))
            self.client_socket.send(encrypted_message)
            self.display_message(full_message, align="right")
            self.message_entry.delete(0, tk.END)

    def display_message(self, message, align="left"):
        self.chat_area.config(state='normal')
        self.chat_area.insert(tk.END, message + '\n', align)
        self.chat_area.tag_configure("left", justify="left")
        self.chat_area.tag_configure("right", justify="right")
        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def exit_chat(self):
        if self.client_socket:
            self.client_socket.close()
        self.root.quit()


# Main function to start the client GUI
def main():
    root = tk.Tk()
    ChatGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
