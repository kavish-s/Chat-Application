---

# Secure Chat Application

This project is a secure chat application that uses **RSA** for key exchange and **AES** for encrypted communication between clients and the server. The server uses a graphical interface to manage and display incoming client messages. The clients have their own GUI to send and receive messages.

## Features

- **RSA Encryption**: Securely exchanges AES keys between the server and clients.
- **AES Encryption**: Symmetric encryption is used to encrypt all chat messages.
- **GUI for Server**: Displays chat messages and logs with the option to enable debugging.
- **GUI for Clients**: Chat interface for clients to send and receive messages.
- **Multi-client support**: The server can handle multiple clients simultaneously.
- **Encrypted key exchange**: Secure transfer of AES key using RSA encryption.

## How It Works

### Key Exchange Process

1. The server generates an **RSA key pair**.
2. The server sends the **RSA public key** to the client when it connects.
3. The client generates a **random AES key** and encrypts it using the server's RSA public key.
4. The client sends the **encrypted AES key** to the server.
5. The server decrypts the AES key using its RSA **private key**.
6. All further messages are encrypted with **AES-256** using this key.

### Chat Communication

- **Clients**: Each client sends messages encrypted using AES-256. The client GUI provides a text area for entering messages, and sent messages are encrypted before transmission.
- **Server**: The server decrypts the AES-encrypted messages, logs them in the GUI, and forwards the encrypted message to other connected clients.

## Dependencies

- Python 3.x
- `cryptography` library: To install, run:
  ```
  pip install cryptography
  ```
- `tkinter`: Pre-installed with Python for GUI creation.

## Files

- `encryption.py`: Contains the AES encryption and decryption methods.
- `server.py`: The server-side script. Handles multiple clients, performs RSA key generation, and logs messages.
- `client.py`: The client-side script. Connects to the server, handles AES key generation, and sends/receives encrypted messages.
- `LICENSE`: Contains the licensing information for the project.

## How to Run

### Server

1. Run the server by executing:
   ```bash
   python server.py
   ```
2. The server GUI will open, showing the chat logs and debug logs (if enabled).
3. Press "Start Server" to begin listening for client connections.

### Client

1. Run the client by executing:
   ```bash
   python client.py
   ```
2. A client GUI will open. Enter an alias and press OK.
3. You can now send and receive encrypted messages in the chat.

### Debug Mode

- On the server GUI, you can enable the "Debug Mode" checkbox to view the encrypted and decrypted messages for debugging purposes.

## Project Structure

```
.
├── encryption.py       # AES encryption/decryption logic
├── server.py           # Server-side logic with RSA key exchange and message handling
├── client.py           # Client-side logic with AES key exchange and message handling
├── LICENSE             # Project licensing information
└── README.md           # Project documentation
```

## Security Considerations

- **RSA** is used for key exchange to protect the AES key during transmission.
- **AES-256** is used for encrypting all chat messages.
- Messages exchanged between clients and server are protected from eavesdropping.

## Future Improvements

- **Authentication**: Add client authentication to ensure only authorized users can join.
- **TLS/SSL**: Use TLS for encrypted communication over sockets.
- **Message Integrity**: Implement HMAC or digital signatures to ensure message integrity.

## Contributors

This project was developed by:
- [Kavish Shah](https://www.linkedin.com/in/-kavish-shah/)
- [Atharva Shinde](https://www.linkedin.com/in/atharvanshinde/)

---

