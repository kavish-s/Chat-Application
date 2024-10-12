import os
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, messagebox

from encryption import AES  # Assuming AES class is in a separate file

# AES key should be 32 bytes (256 bits) for AES-256
aes_key = os.urandom(32)
aes = AES(aes_key)


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

            # Send AES key to the server (in production, use secure key exchange)
            self.client_socket.send(aes_key)

            # Step 2: Send alias to the server
            self.client_socket.send(self.alias.encode('utf-8'))

            # Step 3: Start a thread to receive messages
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.start()

        except Exception as e:
            messagebox.showerror("Connection Error", f"Could not connect to server: {e}")
            self.root.quit()

    def receive_messages(self):
        while True:
            try:
                encrypted_message = self.client_socket.recv(1024)
                if encrypted_message:
                    decrypted_message = aes.decrypt(encrypted_message).decode('utf-8')
                    self.display_message(decrypted_message, align="left")
                else:
                    self.display_message("Server disconnected.", align="left")
                    break
            except Exception as e:
                self.display_message(f"Error receiving message: {e}", align="left")
                break

    def send_message(self, event=None):
        message = self.message_entry.get().strip()
        if message:
            full_message = f"{self.alias}: {message}"
            encrypted_message = aes.encrypt(full_message.encode('utf-8'))
            self.client_socket.send(encrypted_message)
            self.display_message(full_message, align="right")  # Display sender's message on the right
            self.message_entry.delete(0, tk.END)  # Clear the entry field

    def display_message(self, message, align="left"):
        self.chat_area.config(state='normal')

        if align == "right":
            self.chat_area.tag_configure("right", justify='right')
            self.chat_area.insert(tk.END, message + '\n', 'right')
        else:
            self.chat_area.insert(tk.END, message + '\n')

        self.chat_area.config(state='disabled')
        self.chat_area.yview(tk.END)

    def exit_chat(self):
        try:
            # Close the client socket
            if self.client_socket:
                self.client_socket.shutdown(socket.SHUT_RDWR)
                self.client_socket.close()

            # Quit the Tkinter main loop
            self.root.quit()  # Stop the main loop
        except Exception as e:
            messagebox.showerror("Exit Error", f"Error while exiting: {e}")


# Main function to start the chat GUI
def main():
    root = tk.Tk()
    app = ChatGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
