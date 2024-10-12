# Chat Application

## Overview
This is a simple Python chat application designed for educational purposes, demonstrating the use of sockets for communication and AES encryption for secure message transmission. This project is developed as part of the Network Security subject to showcase fundamental networking and cryptography concepts.

## Features
- **Real-time Messaging**: Users can send and receive messages instantly.
- **AES Encryption**: Messages are encrypted using AES (Advanced Encryption Standard) to ensure privacy and security.
- **Client-Server Architecture**: The application consists of a server that manages connections and clients that send and receive messages.
- **Graphical User Interface (GUI)**: The server and client applications have a user-friendly GUI for better interaction and monitoring.

## Technologies Used
- Python
- Sockets (for network communication)
- `cryptography` library (for AES encryption)
- Tkinter (for GUI)

## Installation
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/kavish-s/chat-application.git
   cd chat-application
   ```

2. **Install Required Packages**:
   Make sure you have Python 3 installed. Then, install the required packages:
   ```bash
   pip install cryptography
   ```

## Usage
1. **Start the Server**:
   - Navigate to the project directory and run the server script:
     ```bash
     python server.py
     ```
   - The server will listen for incoming client connections.

2. **Start the Client**:
   - In a new terminal window, navigate to the project directory and run the client script:
     ```bash
     python client.py
     ```
   - Enter your alias when prompted and start sending messages.

3. **Debug Mode**:
   - The server GUI includes a debug mode that allows you to view encrypted messages and their decrypted contents. Check the "Debug Mode" checkbox to enable this feature.

## Code Structure
- `server.py`: Contains the server-side logic and GUI implementation.
- `client.py`: Contains the client-side logic for sending and receiving messages.
- `encryption.py`: Implements the AES encryption and decryption functions.
- `README.md`: Documentation for the project.

## Contributing
Contributions are welcome! Feel free to submit a pull request or open an issue to discuss improvements or bug fixes.

## Acknowledgments
- Inspired by concepts learned in the Network Security course.
- Special thanks to resources and tutorials on Python networking and cryptography.
