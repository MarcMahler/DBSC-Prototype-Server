# Development Log

## Milestone 1: Cookie-based baseline

Implemented:
- Express server
- Login page
- Dummy credentials
- Server-side session store
- Short-lived HttpOnly session cookie
- Protected route
- Logout route

Observed behavior:
- Browser stores the authentication cookie after login.
- The cookie is automatically sent with requests to protected resources.
- Access to the protected page fails after cookie/session expiration.
- Logout removes the session and clears the cookie.

## Milestone 2: Local HTTPS support

Implemented:
- Local HTTPS server using mkcert-generated certificates
- Trusted local certificate authority
- Secure session cookie

Observed behavior:
- The prototype is accessible via https://localhost:3000.
- Chrome accepts the local certificate as trusted.
- The authentication cookie is now marked as Secure and HttpOnly.
- The cookie-based session flow still works as in the HTTP baseline.