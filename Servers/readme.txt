Project Overview

This project implements the Kerberos authentication protocol, a network authentication protocol designed to provide strong authentication for client/server applications by using secret-key cryptography.

Key Components:

- Authentication Server (AS): Responsible for user registration, authentication, and issuing Ticket Granting Tickets (TGTs).

- Message Server (MS): Acts as a service server that clients can communicate with after being authenticated by the AS.

- Client: Represents a user attempting to access services provided by the MS.

Functionality:

- User and Server Registration: Clients and message servers can register with the AS, receiving unique identifiers and establishing long-term secret keys.

- Authentication and Key Distribution: The AS verifies user credentials and issues TGTs, enabling clients to request session keys for communication with specific message servers.

- Secure Message Exchange: Clients can securely exchange messages with message servers using session keys obtained through the Kerberos protocol.

Implementation Details

Languages and Libraries:

- Python 3: Used for both client and server implementations.
- PyCryptodome: Provides cryptographic functionalities for encryption, decryption, and hashing.

Project Structure:

- header.py: Contains shared constants, data structures, and helper functions used by both client and server code.

- aServer.py: Implements the authentication server logic, including user/server registration and key distribution.

- m1Server.py: Implements a specific message server (m1Server) functionality.

- client.py: Implements the client-side logic for user interaction, server communication, and message exchange.

- exploit.py: Demonstrates a dictionary attack against the Kerberos implementation.

- attac-explain-heb.docx: Provides a detailed explanation of the dictionary attack in Hebrew.

Dictionary Attack and Mitigation

Exploit.py showcases a dictionary attack against the Kerberos implementation. It attempts to decrypt intercepted messages using a list of potential passwords, aiming to discover the client's password and gain access to the system.

Possible Mitigation Strategies:

-Strong Password Policies: Enforce complex password requirements with a minimum length, combination of upper/lower case letters, numbers, and special characters.

-Password Salting: Introduce a unique salt value during password hashing to prevent pre-computed rainbow table attacks.

-Rate Limiting: Implement mechanisms to limit the number of login attempts within a specific time frame to thwart brute-force attacks.

-Multi-factor Authentication: Employ additional authentication factors beyond passwords, such as one-time passwords or biometric verification, to enhance security.

Video examples: 

- Servers setup: https://youtu.be/scT7bE3Zk_0

- Exploit: https://youtu.be/8MCh5AE5JO0