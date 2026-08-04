# AZPE product principles

AZPE is guided by ten core design principles that inform its architecture, CLI experience, and result reporting.

---

## 1. Run where the workload runs

AZPE evaluates connectivity from inside the application's runtime environment (container, pod, VM, or local workstation). Observing network paths from the actual execution context is the only way to capture real DNS, routing, firewall, and proxy behaviors.

> [!NOTE]
> **Resolver semantics**: AZPE uses Go's built-in pure-Go resolver behavior (`GO_BUILTIN`) in static Unix releases (`CGO_ENABLED=0`), which parses system DNS configuration files (`/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`). Diagnostic output explicitly reports `Resolver mode: Go built-in` in `--details` and JSON (`"resolverMode": "GO_BUILTIN"`).

---

## 2. No Azure permission required by default

Default operation must never require Azure credentials, Azure CLI, Azure SDK, subscription access, or control-plane permissions. Workloads running in enterprise environments often lack control-plane access.

---

## 3. Plain language first; technical evidence remains available

Default terminal output presents simple, non-jargon diagnostic answers designed for application developers:
- What happened?
- Which team probably owns the problem?
- What action should be taken next?

Detailed technical observations (DNS records, TLS ciphers, HTTP status codes) remain accessible via `--details` and `--json`.

---

## 4. Workload system trust store enforcement; no verification bypasses

AZPE strictly evaluates certificate trust against the host execution environment's native operating system trust store (`RootCAs: nil`). No CLI flags are provided to supply custom CA bundles or bypass certificate verification (`InsecureSkipVerify: false`). Missing enterprise CAs or untrusted certificates are reported directly as diagnostic findings (*The certificate is not trusted by this workload*) rather than silently worked around.

---

## 5. Never confuse network success with application authorization

A successful TCP connection or valid TLS handshake does not guarantee application access. Conversely, an HTTP 401 or 403 status code indicates that TCP, TLS, and HTTP transport to a responder for this hostname succeeded, although an intermediary may have generated the response. AZPE evaluates network path health independently from application authorization.

---

## 6. Never claim more certainty than the evidence supports

Without Azure control-plane access, observing resolution to a private IP (RFC 1918 / RFC 4193) is evidence, not absolute proof, of reaching an authorized Azure Private Endpoint. AZPE will never output `Private Endpoint verified`.

---

## 7. One binary and one primary command

AZPE is distributed as a single, statically linked binary without runtime dependencies. The core user workflow centers on a single primary command:

```bash
azpe probe <target>
```

> [!NOTE]
> **PowerShell compatibility client (`POWERSHELL_COMPAT`)**: For restricted Windows environments (e.g., Azure Virtual Desktop, AppLocker-managed session hosts) where arbitrary native `.exe` binaries are restricted, AZPE provides an official PowerShell compatibility client (`Invoke-AzpeProbe`). It adheres strictly to enterprise application controls and reports capability metadata (`"engine": { "name": "POWERSHELL_COMPAT", "version": "VERSION" }`).

---

## 8. Diagnose, do not modify

AZPE is strictly a diagnostic tool. It will read network signals but will never mutate environment settings, modify DNS entries, alter route tables, or edit configuration files.

---

## 9. No automatic remediation

AZPE delivers actionable diagnosis and next steps for human operators or automated pipelines, but does not perform automated remediation actions.

---

## 10. Output must be useful to both application and network teams

By providing plain-language summaries alongside structured JSON data and detailed diagnostic breakdowns, AZPE bridges the communication gap between application developers and central network/security infrastructure teams.
