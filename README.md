# SecureChat - End-to-End Encrypted Messaging

SecureChat is a private, end-to-end encrypted messaging platform that ensures secure communication. With OAuth2 authentication, SSL encryption, and WebSocket-based real-time messaging, SecureChat is built for privacy and ease of use. It runs seamlessly with Docker Compose.

## Features

- **End-to-End Encryption**: All messages are encrypted, ensuring privacy.
- **OAuth2 Login**: Secure authentication using OAuth2.
- **SSL Encryption**: All web traffic is encrypted using SSL.
- **WebSocket Communication**: Real-time messaging with socket-based server-client communication.
- **Room Management**: Users can create, edit, leave, and invite others to rooms.
- **Docker Deployment**: Easily deploy and manage using Docker Compose.

## Requirements

- Docker and Docker Compose installed on your system.
- Register a Google OAuth2 app for login.
- Include the OAuth2 keys in a `.env` file.
- SSL certificates (if deploying with a custom domain).

## Setup Instructions

Clone the repository and navigate to the project directory:

```sh
git clone https://github.com/blox-dev/SecureChat.git
cd securechat
```

Build and start the application using Docker Compose:

```sh
npm install
docker-compose build
docker-compose up
```

The application should now be running. Access it via `http://localhost:PORT` (replace PORT with your configured port, default 3000).

## Reset Instructions

To completely reset the application, including removing volumes and rebuilding the containers, run:

```sh
docker-compose down -v
docker-compose build
docker-compose up
```

## Security Considerations

- Ensure OAuth2 credentials are stored securely.
- Use strong SSL certificates for encrypted communication.
- Regularly update dependencies to patch security vulnerabilities.
