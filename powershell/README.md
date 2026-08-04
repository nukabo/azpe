# AZPE PowerShell compatibility client

An official PowerShell compatibility client for **AZPE** (Azure Private Endpoint Connectivity Diagnostic Utility) designed for restricted Windows environments such as:
- Azure Virtual Desktop (AVD) session hosts
- Enterprise-managed Windows workstations
- Restricted jump hosts
- Environments governed by AppLocker or Windows Defender Application Control (WDAC)
- Environments where arbitrary downloaded `.exe` files cannot easily be executed

---

## Technical identity & guarantees

- **Engine name**: `POWERSHELL_COMPAT` (`VERSION`)
- **Reference implementation**: Native Go binary (`NATIVE`) remains the reference implementation and highest-fidelity engine.
- **No security-control bypass**: Operates strictly within enterprise security controls. Does **NOT** bypass, evade, or weaken AppLocker, WDAC, Microsoft Defender, SmartScreen, PowerShell Execution Policies, or Constrained Language Mode (CLM).
- **Constrained Language Mode**: Detects Constrained Language Mode and degrades safely where restricted operations are unavailable.
- **TCP timeout behavior**: In PowerShell compatibility mode, the Windows TCP diagnostic command (`Test-NetConnection`) may exceed `-TimeoutSeconds` in some environments.
- **Zero credentials / Zero Azure login**: Operates out-of-band against DNS and network sockets. Never requires `az login`, `Connect-AzAccount`, or Azure subscriptions.

---

## Supported usage patterns

### 1. Temporary standalone usage (no module installation)

```powershell
# Unblock downloaded file if necessary
Unblock-File .\Invoke-AzpeProbe.ps1

# Run diagnostic probe
.\Invoke-AzpeProbe.ps1 myvault.vault.azure.net
```

### 2. Local module import

```powershell
Import-Module .\Azpe\Azpe.psd1
Invoke-AzpeProbe myvault.vault.azure.net
```

### 3. Enterprise-installed module

```powershell
Import-Module Azpe
Invoke-AzpeProbe myvault.vault.azure.net
```

---

## Command options

```powershell
Invoke-AzpeProbe [-Target] <string> [-TimeoutSeconds <int>] [-Detailed] [-Json] [-NoHttp] [-NoColor]
```

| Parameter | Type | Default | Description |
| --------- | ---- | ------- | ----------- |
| `-Target` | `string` | Optional | Target Azure service FQDN or URL (e.g. `myvault.vault.azure.net`) |
| `-TimeoutSeconds` | `int` | `5` | Probe operation deadline timeout in seconds |
| `-Detailed` | `switch` | `false` | Enables multi-section detailed terminal diagnostic output |
| `-Json` | `switch` | `false` | Emits machine-readable JSON (`schemaVersion: 1`) to stdout |
| `-NoHttp` | `switch` | `false` | Skips minimal HTTP probe phase and returns Phase 4 TLS results |
| `-NoColor` | `switch` | `false` | Disables colorized terminal output |

---

## Enterprise deployment & Authenticode code-signing

For enterprise deployment in AppLocker/WDAC governed environments:

1. Build or download the official release assets (`azpe-powershell_VERSION.zip`).
2. Sign `Azpe.psd1`, `Azpe.psm1`, `Public/*.ps1`, `Private/*.ps1`, and `Invoke-AzpeProbe.ps1` with your organization's approved Enterprise Code-Signing Certificate:
   ```powershell
   Set-AuthenticodeSignature -FilePath .\Invoke-AzpeProbe.ps1 -Certificate (Get-Item Cert:\CurrentUser\My\<Thumbprint>)
   ```
3. Verify signature:
   ```powershell
   Get-AuthenticodeSignature .\Invoke-AzpeProbe.ps1
   ```
4. Distribute through your endpoint-management team (Intune / SCCM / GPO).

> [!IMPORTANT]
> **Policy compliance disclaimer**: Do not instruct users to bypass policies or run `Set-ExecutionPolicy Unrestricted`. Instruct users to ask their Windows platform or endpoint-management team to approve and distribute AZPE through the organization's normal software channel.
