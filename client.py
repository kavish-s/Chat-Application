import os
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

# Import necessary cryptographic modules
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

# Import AES encryption class
from encryption import AES


# Class to manage the chat interface (GUI) and network communication
class ChatGUI:
    def __init__(self, root):
        # Initialize the root window with title and size
        self.root = root
        self.root.title("Secure Chat Application")
        self.root.geometry("400x500")

        # Variables to hold alias and client socket connection
        self.alias = ""
        self.client_socket = None

        # Set up the chat area (a scrolled text widget)
        self.chat_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled', height=15)
        self.chat_area.pack(pady=10)

        # Message entry field where users will type messages
        self.message_entry = tk.Entry(root, width=40)
        self.message_entry.pack(pady=5, padx=10)
        self.message_entry.bind("<Return>", self.send_message)  # Send message on pressing Enter

        # Button to send the message
        self.send_button = tk.Button(root, text="Send", command=self.send_message)
        self.send_button.pack(pady=5)

        # Add an exit button to allow users to exit the chat gracefully
        self.exit_button = tk.Button(root, text="Exit", command=self.exit_chat)
        self.exit_button.pack(pady=5)

        # Label and entry field for the user to input their alias (on the same canvas)
        self.alias_label = tk.Label(root, text="Please enter your alias:")
        self.alias_label.pack(pady=10)

        self.alias_entry = tk.Entry(root)
        self.alias_entry.pack(pady=5)

        # Button to confirm the alias
        self.alias_button = tk.Button(root, text="OK", command=self.set_alias)
        self.alias_button.pack(pady=10)

    # Method to set the alias after it's entered
    def set_alias(self):
        alias = self.alias_entry.get().strip()  # Get and strip any whitespace from the alias
        if alias:
            self.alias = alias  # Set the alias if it's not empty
            # Remove alias input widgets after alias is set
            self.alias_label.pack_forget()
            self.alias_entry.pack_forget()
            self.alias_button.pack_forget()
            self.connect_to_server()  # Proceed to connect to the server
        else:
            messagebox.showerror("Error", "Alias cannot be empty!")  # Show error if alias is empty

    # Method to connect to the server and handle key exchange
    def connect_to_server(self):
        try:
            # Create a socket and connect to the server
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect(('127.0.0.1', 9999))  # Connect to server on localhost

            # Step 1: Receive the server's RSA public key
            rsa_public_key = serialization.load_pem_public_key(
                self.client_socket.recv(1024), backend=default_backend())

            # Step 2: Generate a random AES key and encrypt it using the server's RSA public key
            aes_key = os.urandom(32)  # Generate 32-byte (256-bit) AES key
            encrypted_aes_key = rsa_public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),  # Padding and hash algorithm
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Step 3: Send the encrypted AES key to the server
            self.client_socket.send(encrypted_aes_key)

            # Initialize AES cipher with the generated AES key
            self.aes = AES(aes_key)

            # Send the user's alias to the server
            self.client_socket.send(self.alias.encode('utf-8'))

            # Start a new thread to receive messages from the server
            threading.Thread(target=self.receive_messages, daemon=True).start()

        except Exception as e:
            # Display an error message if connection or key exchange fails
            messagebox.showerror("Error", f"Error connecting to server: {e}")
            self.root.quit()  # Close the application

    # Method to continuously receive messages from the server
    def receive_messages(self):
        try:
            while True:
                # Receive an encrypted message from the server
                encrypted_message = self.client_socket.recv(1024)
                if encrypted_message:
                    # Decrypt the message and display it in the chat area
                    message = self.aes.decrypt(encrypted_message).decode('utf-8')
                    self.display_message(message)
                else:
                    break  # Break the loop if no message is received
        except Exception as e:
            # Display any errors encountered during message reception
            self.display_message(f"Error receiving message: {e}")

    # Method to send a message to the server
    def send_message(self, event=None):
        message = self.message_entry.get().strip()  # Get the typed message
        if message:
            # Format the message to include the alias
            full_message = f"{self.alias}: {message}"
            # Encrypt the message before sending
            encrypted_message = self.aes.encrypt(full_message.encode('utf-8'))
            self.client_socket.send(encrypted_message)  # Send the encrypted message to the server
            # Display the sent message in the chat area (right-aligned)
            self.display_message(full_message, align="right")
            self.message_entry.delete(0, tk.END)  # Clear the message entry field

    # Method to display a message in the chat area
    def display_message(self, message, align="left"):
        self.chat_area.config(state='normal')  # Enable editing in the chat area
        self.chat_area.insert(tk.END, message + '\n', align)  # Insert the message
        # Configure alignment for messages
        self.chat_area.tag_configure("left", justify="left")
        self.chat_area.tag_configure("right", justify="right")
        self.chat_area.config(state='disabled')  # Disable editing again
        self.chat_area.yview(tk.END)  # Scroll to the bottom to show the latest message

    # Method to exit the chat and close the connection
    def exit_chat(self):
        if self.client_socket:
            self.client_socket.close()  # Close the client socket if it exists
        self.root.quit()  # Close the GUI


# Main function to start the chat client GUI
def main():
    root = tk.Tk()  # Create the root window
    ChatGUI(root)  # Initialize the Chat GUI
    root.mainloop()  # Start the Tkinter main loop to keep the window open


# Entry point to run the chat application
if __name__ == "__main__":
    main()
