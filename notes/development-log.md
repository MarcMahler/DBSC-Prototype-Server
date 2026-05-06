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