# Awesome AZD submission readiness

Do not submit automatically or mutate the `Azure/awesome-azd` repository from this template. Use the official [contribution guide](https://azure.github.io/awesome-azd/docs/contribute/) and [template submission issue](https://github.com/Azure/awesome-azd/issues/new?template=template-submission.yml) only after this repository is public, the stack is merged, and the checklist is complete.

## Prerequisite checklist

- [ ] Default branch contains the complete merged stack and passing non-deploying CI.
- [ ] Repository description, license, README, and source URL are current.
- [ ] Suggested topics are reviewed: `azure-developer-cli`, `azd-template`, `bicep`, `microsoft-entra`, `global-secure-access`, `zero-trust`, and `powershell`.
- [ ] `azure.yaml` loads with the documented minimum azd version.
- [ ] The architecture Mermaid source has been exported to a clear gallery image without replacing the text source.
- [ ] Beta/preview APIs, commercial-cloud restrictions, manual connector/router prerequisites, and production-hardening limits are visible.
- [ ] Sample configuration is secret-free and mutation gates remain disabled.
- [ ] No live tenant result, identifier, hostname, credential, certificate private material, or sensitive traffic evidence is included.
- [ ] A stable UUID is generated specifically for the gallery entry if the contribution workflow requests one.

## Copy-ready submission fields

**Source repository:** `https://github.com/nathanmcnulty/azd-global-secure-access`

**Template title:** Microsoft Entra Global Secure Access secure POC

**Description:** Provisions a conservative Azure foundation for a Microsoft Entra Global Secure Access proof of concept, with exact-ID ownership, atomic state, non-destructive cleanup planning, discovery-first observability, client evidence, and strongly gated Microsoft Graph beta remote-network readiness. Tenant mutations are disabled by default, and router and connector changes remain manual.

**Author type:** Community

**Infrastructure as code:** Bicep

**Languages/tools:** PowerShell

**Suggested Azure services:** Key Vault, Storage, Log Analytics

**Additional information:** Requires Azure Developer CLI 1.30.0 or later. Microsoft Graph beta and preview logging surfaces are explicitly gated and not presented as production-supported. Validate licensing, cloud support, permissions, connector/CPE prerequisites, Conditional Access exclusions, and organizational production controls before use.
