# Bulletin Board System (BBS)

## Overview

This repository contains the implementation of a secure Bulletin Board System (BBS), developed as a project for the Foundations of Cybersecurity/Applied Cryptography course (2023-24). The BBS allows registered users to read messages from other users and post their own in a secure environment.

## Features

- **User Registration and Authentication**: Secure user registration with email verification and login functionality
- **Message Management**: List, get, and add messages to the bulletin board
- **Secure Communication**: All operations are performed over secure channels with cryptographic protection
- **Perfect Forward Secrecy**: Ensures that session keys will not be compromised even if long-term keys are exposed

## System Architecture

The BBS is implemented as a centralized server that handles all user operations and message storage. The server is identified by a fixed IP address and port number, and uses a public-private key pair for cryptographic operations.

### Key Components

1. **BBS Server**: Central server that manages users, messages, and handles all operations
2. **Client Application**: Allows users to interact with the BBS server
3. **Database**: Stores user information and messages securely

## Security Features

- **Password Protection**: Passwords are never stored or transmitted in plaintext
- **Secure Communications**: Implementation provides confidentiality, integrity, replay protection, and non-malleability
- **Perfect Forward Secrecy (PFS)**: Session keys are generated using ephemeral keys to provide PFS
- **Email Verification**: User registration requires email verification through a challenge-response mechanism
- **Session Management**: Secure sessions established after login and maintained until logout

## Implementation Details

The system is implemented in C/C++ using the OpenSSL library (without using the OpenSSL API TLS) to provide cryptographic functionality.

### Message Structure
- **Identifier**: Unique identifier for each message
- **Title**: Subject or title of the message
- **Author**: Nickname of the user who posted the message
- **Body**: Content of the message

### User Operations
- **List(int n)**: Lists the latest n messages available in the BBS
- **Get(int mid)**: Downloads a specific message identified by mid
- **Add(String title, String author, String body)**: Adds a new message to the BBS

## Setup and Installation

### Prerequisites
- C/C++ compiler (GCC or equivalent)
- OpenSSL library
- Make/CMake for building

### Building the Project
```bash
git clone https://github.com/contisimone99/Bulletin-Board-System.git
cd bbs-system
make
```

### Running the Server
```bash
./bbs_server
```

### Running the Client
```bash
./bbs_client [server_ip] [server_port]
```

## Usage

### Registration
1. Launch the client application and select "Register"
2. Enter your email address, desired nickname, and password
3. Check your email for the challenge message
4. Enter the challenge in the client application to complete registration

### Login
1. Launch the client application and select "Login"
2. Enter your nickname and password
3. Upon successful login, you will gain access to the BBS operations

### BBS Operations
- To list the latest messages: `list [number_of_messages]`
- To get a specific message: `get [message_id]`
- To add a new message: `add [title] [message_body]`
- To logout: `logout`

## Implementation Challenges

- Implementing secure communication without using OpenSSL's TLS API
- Designing a protocol that guarantees Perfect Forward Secrecy
- Ensuring proper handling of user credentials and session management
- Minimizing code vulnerabilities while maintaining functionality

## Contributors

- Simone Conti

## License
This project is licensed under the MIT License. See LICENSE for details.
