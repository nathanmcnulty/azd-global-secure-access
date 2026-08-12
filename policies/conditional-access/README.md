# Conditional Access review templates

These files are evidence and review inputs, not deployment payloads. The template never imports or enables them automatically.

- Every policy starts in report-only mode.
- Replace every placeholder with a reviewed object ID.
- Keep at least two cloud-only emergency access accounts excluded and validate them from an out-of-band path that does not depend on Global Secure Access.
- Use a pilot group, review policy impact and sign-in evidence, and account for propagation before considering enforcement.
- For compliant-network policy, verify source IP restoration and signaling first. A policy assignment does not prove that the endpoint's traffic was acquired.
- Do not combine these examples into a broad all-users policy without a separate change record, rollback plan, and emergency access test.

References:

- https://learn.microsoft.com/entra/identity/conditional-access/concept-conditional-access-report-only
- https://learn.microsoft.com/entra/identity/role-based-access-control/security-emergency-access
- https://learn.microsoft.com/entra/global-secure-access/concept-universal-conditional-access
- https://learn.microsoft.com/entra/global-secure-access/how-to-compliant-network
