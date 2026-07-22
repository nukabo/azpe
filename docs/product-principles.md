# AZPE Product Principles

AZPE is guided by ten core design principles that inform its architecture, CLI experience, and result reporting.

---

### 1. Run where the workload runs
AZPE evaluates connectivity from inside the application's runtime environment (container, pod, VM, or local workstation). Observing network paths from the actual execution context is the only way to capture real DNS, routing, firewall, and proxy behaviors.

---

### 2. No Azure permission required by default
Default operation must never require Azure credentials, Azure CLI, Azure SDK, subscription access, or control-plane permissions. Workloads running in enterprise environments often lack control-plane access.

---

### 3. Plain language first; technical evidence remains available
Default terminal output presents simple, non-jargon diagnostic answers designed for application developers:
- What happened?
- Which team probably owns the problem?
- What action should be taken next?

Detailed technical observations (DNS records, TLS ciphers, HTTP status codes) remain accessible via `--details` and `--json`.

---

### 4. Never confuse network success with application authorization
A successful TCP connection or valid TLS handshake does not guarantee application access. Conversely, an HTTP 401 or 403 status code proves that the network path and service are healthy, but credential/identity configuration is failing. AZPE evaluates network path health independently from application authorization.

---

### 5. Never claim more certainty than the evidence supports
Without Azure control-plane access, observing resolution to a private IP (RFC 1918 / RFC 4193) is evidence, not absolute proof, of reaching an authorized Azure Private Endpoint. AZPE will never output `Private Endpoint verified`.

---

### 6. One binary and one primary command
AZPE is distributed as a single, statically linked binary without runtime dependencies. The core user workflow centers on a single primary command:
```bash
azpe probe <target>
```

---

### 7. Diagnose, do not modify
AZPE is strictly a diagnostic tool. It will read network signals but will never mutate environment settings, modify DNS entries, alter route tables, or edit configuration files.

---

### 8. No automatic remediation
AZPE delivers actionable diagnosis and next steps for human operators or automated pipelines, but does not perform automated remediation actions.

---

### 9. No AI runtime dependency
AZPE relies on deterministic logic, explicit state models, and established network rules. It contains no AI/LLM runtime dependencies.

---

### 10. Output must be useful to both application and network teams
By providing plain-language summaries alongside structured JSON data and detailed diagnostic breakdowns, AZPE bridges the communication gap between application developers and central network/security infrastructure teams.
