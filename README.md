# DBSC Server Prototype

This project is a prototype server implementation of **Device Bound Session Credentials (DBSC)**, developed as part of a Bachelor's Thesis. It demonstrates how session security can be enhanced by binding session cookies to a specific device using cryptographic keys.

## Overview

The DBSC Server provides a proof-of-concept for the DBSC protocol, which aims to mitigate session hijacking (cookie theft) by requiring a device-bound cryptographic proof for session maintenance and sensitive operations.

## Features

- **Standard Authentication**: Basic login/logout flow with session cookies.
- **DBSC Registration**: Allows clients to register a device-bound public key for a session.
- **DBSC Session Refresh**: Periodic session renewal requiring a cryptographic proof (JWT signed by the device's private key).
- **Challenge-Response Mechanism**: Server issues challenges that must be included in the client's proof.
- **Measurements**: Optional measurement logging for performance analysis.
- **Secure Logging**: Detailed console logging of HTTP requests, session events, and DBSC operations using `picocolors`.
- **HTTPS Support**: Configured to run over HTTPS to meet DBSC's secure transport requirements.

## Technologies

- **Runtime**: Node.js
- **Framework**: Express.js
- **Authentication**: `cookie-parser` for session management.
- **Cryptography**: Node's built-in `crypto` module (ES256 for JWT verification).
- **Development**: `nodemon` for automatic restarts.

## Prerequisites

- [Node.js](https://nodejs.org/) (v18+ recommended)
- SSL/TLS Certificates: The server expects certificates in the `certs/` directory (`localhost-key.pem` and `localhost.pem`).

## Installation

1. Clone the repository:
   ```bash
   git clone <repository-url>
   cd DBSC_Server
   ```

2. Install dependencies:
   ```bash
   npm install
   ```

3. Ensure certificates are present:
   Place your `localhost-key.pem` and `localhost.pem` in the `certs/` folder.

## Running the Server

### Development Mode
Runs the server with `nodemon` for automatic reloading on file changes:
```bash
npm run dev
```

### Development Mode with Measurements
Runs the server with `nodemon` and enabled measurement logging:
```bash
npm run dev:m
```

### Production Mode
Starts the server normally:
```bash
npm start
```

The server will be available at `https://localhost:3000` (or the configured port).

## Project Structure

- `src/server.js`: Main entry point and Express route definitions.
- `src/dbsc.js`: Core logic for DBSC (JWT verification, challenge management).
- `src/sessions.js`: Simple in-memory session management.
- `src/logger.js`: Custom logging utility.
- `src/measurement.js`: Measurement utility for performance tracking.
- `src/measurements.ndjson`: Log file for measurement data.
- `certs/`: (External) Directory for SSL certificates.
- `notes/`: Project documentation and development logs.

## DBSC Flow in this Prototype

1. **Login**: User authenticates normally via `/login`.
2. **Registration**: The client sends a public key to `/dbsc/register` using the `Secure-Session-Response` header. The server creates a DBSC session linked to the auth session.
3. **Challenge/Refresh**: When a refresh is needed (e.g., requested by the browser or triggered by expiry), the client hits `/dbsc/refresh`. 
   - If no proof is provided, the server returns a 403 with a `Secure-Session-Challenge`.
   - The client then retries with a signed JWT in the `Secure-Session-Response` header.
   - Upon successful verification, the server renews the `auth_cookie`.

## License

This project is licensed under the ISC License.
