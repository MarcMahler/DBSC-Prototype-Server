# Prototype Evaluation Hypotheses

This file documents the hypotheses that guide the practical evaluation of the DBSC prototype.  
The hypotheses are derived from the preceding theoretical analysis of Device-Bound Session Credentials and focus on practical aspects of implementation, integration, and deployment.

The goal is not to test basic cryptographic assumptions that already follow from the DBSC design. Instead, the prototype is used to examine where practical complexity arises when a DBSC-style renewal mechanism is integrated into a conventional cookie-based web application.

---

## Hypothesis List

### H1 — Integration Scope

**Integrating a DBSC-style renewal mechanism mainly affects session lifecycle management and server-side state, while ordinary application routes can remain largely unchanged.**

This hypothesis examines whether DBSC can be added as an extension to an existing cookie-based architecture, rather than requiring a complete redesign of application routes and authentication logic.

---

### H2 — Implementation Complexity

**The main implementation complexity lies in handling renewal timing, challenge validity, cookie expiration, and failure cases rather than in the cryptographic signature verification itself.**

This hypothesis focuses on where the practical engineering effort occurs during implementation. It assumes that the cryptographic operations are comparatively straightforward, while the surrounding session lifecycle introduces more complexity.

---

### H3 — Cookie Lifetime Trade-off

**Shorter cookie lifetimes strengthen DBSC’s protection against replay of stolen cookies, but increase renewal frequency and make failure handling more relevant.**

This hypothesis addresses the trade-off between security and operational overhead. Short-lived cookies reduce the useful lifetime of stolen credentials, but they also require more frequent renewal and more robust handling of expired or failed sessions.

---

### H4 — Deployment Dependencies

**Practical adoption of DBSC depends not only on server-side implementation effort, but also on browser-controlled behavior, secure contexts, and platform support.**

This hypothesis evaluates whether DBSC deployment is limited by factors outside the web application itself, such as browser support, restricted security headers, HTTPS requirements, TPM availability, and experimental platform behavior.

---

## Evaluation Focus

The prototype evaluation will therefore focus on:

- required server-side changes,
- session and DBSC state management,
- renewal and failure handling,
- effects of cookie lifetime choices,
- browser-controlled behavior and local secure-context requirements.

These hypotheses will be revisited after implementing and testing the prototype.