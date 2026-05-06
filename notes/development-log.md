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

## Milestone 3: DBSC endpoint skeletons

Implemented:
- DBSC session store
- `/dbsc/register` endpoint
- `/dbsc/refresh` endpoint
- challenge generation for refresh requests
- debug endpoint for inspecting DBSC sessions
- fallback `X-DBSC-Session-Id` header for manual local testing

Observed behavior:
- Manual registration creates a DBSC session associated with the current authenticated session.
- A refresh request with a known DBSC session ID returns `403 Forbidden`.
- The server includes a challenge in the `Secure-Session-Challenge` response header.
- The fallback `X-DBSC-Session-Id` header is used only for manual testing, because browser-controlled `Sec-*` headers cannot be set by page JavaScript.


