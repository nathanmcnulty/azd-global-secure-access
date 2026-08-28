# Agent-assisted deployment

An agent can help prepare and validate this proof of concept, but it does not inherit authority to change Azure, Microsoft Entra, Intune, Conditional Access, certificates, or network traffic.

## Safe agent tasks

Within an administrator's request, an agent may:

- verify local prerequisites and repository state;
- initialize the template and explain the configuration choices;
- inspect the safe example without copying tenant secrets into source control;
- run Bicep, PowerShell, Pester, and read-only readiness validation;
- summarize the preview, ownership manifest, pending transaction, and cleanup plan;
- compare post-deployment evidence with the administrator's reviewed intent.

Use normal cached operating-system broker or browser authentication. An agent must never start or recommend device-code authentication, extract tokens, expose pre-shared keys, or work around a consent or tenant mismatch.

## Administrator decisions

The administrator must explicitly approve:

- Azure provisioning and role assignments;
- Microsoft Graph beta acceptance and each tenant mutation surface;
- adoption of any existing object;
- forwarding-profile state changes and pilot assignments;
- certificate signing, upload, enablement, or rotation;
- Intune assignments, Conditional Access changes, and remote-network execution;
- cleanup of any tenant object.

Before a write, verify the signed-in account, Azure tenant and subscription, Microsoft Graph tenant and cloud, requested scopes, target object IDs, feature gates, and the current read-only plan. Matching display names are not proof of ownership.

## Suggested workflow

1. Ask the agent to initialize the template and explain every non-default choice.
2. Run the Azure preview and GSA readiness report without mutation.
3. Review unsupported, beta, unknown, reused, and unmanaged findings.
4. Authorize only the smallest pilot capability needed for the test.
5. Run `azd up` while the administrator handles normal browser consent.
6. Compare deployed resources and exact tenant object IDs with the reviewed plan.
7. Test from a pilot device and record the result before expanding scope.
8. Generate and review the cleanup plan separately from deployment.

If authentication, licensing, consent, connector health, cloud support, or stale evidence blocks the workflow, stop and resolve the boundary rather than bypassing it.
