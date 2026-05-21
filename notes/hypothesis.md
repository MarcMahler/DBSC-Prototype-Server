# Prototype Evaluation Hypotheses

This file documents the hypotheses that guide the practical evaluation of the DBSC prototype.  
The hypotheses are derived from the preceding theoretical analysis of Device-Bound Session Credentials and focus on
practical aspects of implementation, integration, and deployment.

The goal is not to test basic cryptographic assumptions that already follow from the DBSC design. Instead, the prototype
is used to examine where practical complexity arises when a DBSC-style renewal mechanism is integrated into a
conventional cookie-based web application.

---

## Hypothesis List

### H1 — Ease of Server-Side Integration

**Server sided DBSC support can be integrated into a conventional cookie-based server with limited implementation
effort, since the
required modifications are mainly confined to adding a registration endpoint, a refresh endpoint, and DBSC-specific
session
state management.**

This hypothesis examines whether DBSC can be introduced as a lightweight extension to existing cookie-based session
handling rather than as a major redesign of the server’s authentication architecture. It is supported if the prototype
shows that ordinary authenticated routes can remain largely unchanged and that the main implementation effort is
concentrated in DBSC-specific endpoints and session metadata.

---

### H2 — User-Transparent Session Renewal

**Using DBSC as a cookie renewal mechanism removes the need for active user involvement during session continuation
because the renewal process is performed transparently by the browser and server without user interaction.**

This hypothesis examines whether DBSC can preserve session continuity while keeping the user outside the renewal flow.
It is supported if short-lived session cookies can be renewed through the DBSC refresh mechanism without user
interaction or frontend-triggered actions. It is rejected if the user must actively participate in the renewal process,
for example by re-authenticating, confirming a prompt, or manually triggering session renewal.
---

### H3 — Deployment Dependency

**The feasibility of DBSC adoption depends not only on server implementation effort, but also on environmental
requirements such as HTTPS, browser feature support, and device-backed key storage availability.**

This hypothesis examines whether practical deployment is constrained by factors outside the web application server. It
is supported if the prototype requires a trusted secure context, a DBSC-capable browser, browser flags or experimental
support, and compatible device security features. It is rejected if DBSC can be evaluated and deployed independently of
such platform conditions.

---

### H4 — Preservation of Application-Level Cookie Semantics

**DBSC changes the renewal and security properties of session cookies without changing their application-level role as
the indicator of an authenticated session.**

This hypothesis examines whether authenticated routes can continue to treat the session cookie as the basis for access
control, while DBSC modifies how that cookie is issued, bound, and renewed. It is supported if application routes still
rely on ordinary session-cookie validation after DBSC integration. It is rejected if DBSC requires replacing
cookie-based authentication with a different application-level authentication mechanism.

---

### H5 — Separation Between Application Session and DBSC Session State

**A practical DBSC server implementation cannot rely solely on conventional application session storage but requires a
separate DBSC-specific session state for registration, renewal, and proof-of-possession handling.**

This hypothesis examines whether DBSC can be managed using the same state model as conventional session cookies, or
whether additional DBSC-specific state must be maintained separately. It is supported if the implementation requires
distinct tracking of application session identifiers, DBSC session identifiers, public keys, challenges, refresh URLs,
and cookie renewal metadata. It is rejected if the existing application session store alone is sufficient to support
registration and renewal without an additional DBSC-specific state.

