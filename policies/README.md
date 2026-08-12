# Client policy guidance

These notes capture the reusable behavior from the original Windows, macOS, and iOS/iPadOS policy artifacts without replaying tenant-specific exported policy IDs.

No policy in this directory is automatically imported or assigned.

## Windows

For pilot devices:

- Disable QUIC in Microsoft Edge and Google Chrome.
- Disable Secure DNS/DoH and the browser built-in DNS client.
- Review the GSA client registry settings:
  - `RestrictNonPrivilegedUsers`
  - `HideSignOutButton`
  - `HideDisablePrivateAccessButton`
  - `HideDisableButton`
- Prefer IPv4 over IPv6 only after assessing application impact. The common Windows value is `DisabledComponents=32`; treat this as a network architecture decision, not a universal default.
- Consider blocking outbound UDP/443 at the network boundary during pilot validation.

Use Settings Catalog/ADMX settings when available rather than remediation scripts. Deploy registry remediation only through a reviewed Intune detection/remediation package.

References:

- [Install the Windows client](https://learn.microsoft.com/entra/global-secure-access/how-to-install-windows-client)
- [GSA client registry keys](https://learn.microsoft.com/entra/global-secure-access/how-to-install-windows-client#client-registry-keys)

## macOS

The original policy set addressed:

- Microsoft system extension approval for team ID `UBF8T346G9`;
- `com.microsoft.globalsecureaccess` and `com.microsoft.globalsecureaccess.tunnel`;
- a transparent proxy payload using the GSA tunnel provider;
- disabling QUIC and Secure DNS;
- tray controls such as quit and Private Access disable visibility.

Recreate these settings from current Microsoft payload guidance. Do not import old exported Settings Catalog JSON without removing tenant object IDs and validating current setting-definition IDs.

Prerequisites include:

- supported macOS version;
- Company Portal registration;
- Enterprise SSO plug-in;
- current GSA PKG;
- system extension and transparent proxy approval.

Reference: [Install the macOS client](https://learn.microsoft.com/entra/global-secure-access/how-to-install-macos-client).

## iOS/iPadOS

GSA uses Microsoft Defender for Endpoint as the host application. For supervised devices:

- configure the `issupervised` app configuration value;
- deploy Microsoft's current zero-touch control filter payload;
- create the GSA VPN profile with the documented GSA key/value pairs;
- deploy Defender for Endpoint;
- stage assignment to a pilot group.

Do not rehost a downloaded Microsoft mobileconfig in this repository. Download the current payload from Microsoft when preparing deployment.

Reference: [Install the iOS client](https://learn.microsoft.com/entra/global-secure-access/how-to-install-ios-client).

## Android

Deploy Microsoft Defender for Endpoint with GSA enabled. This template can create trusted-root profiles for Android Enterprise Device Owner and Work Profile.

- Android Device Administrator is excluded.
- Android AOSP Device Owner trusted-root creation remains manual until a validated standalone typed Graph resource is documented.

## Assignment safety

Use a dedicated pilot device group first. Validate:

1. client health and registration;
2. root-certificate presence;
3. forwarding-profile acquisition;
4. DNS and browser behavior;
5. TLS inspection with representative applications;
6. bypass requirements for certificate pinning or mutual TLS.

Only expand assignment after rollback and break-glass paths are tested.
