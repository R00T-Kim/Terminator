# OWASP MASTG Mobile Security Testing Guide — Technique Reference

**Version**: 1.0 | **Date**: 2026-02-24 | **Scope**: Android + iOS | **Use**: Bug Bounty Mobile App Testing

---

## MASVS Vulnerability Categories (Quick Map)

| Category | Focus | Key Tests |
|----------|-------|-----------|
| **MASVS-STORAGE** | Data at rest | Shared Prefs, SQLite, Keystore, backups, logs |
| **MASVS-CRYPTO** | Cryptography | Random number generation, key management, algorithms |
| **MASVS-AUTH** | Auth/Session | Biometric bypass, session token handling, reauth |
| **MASVS-NETWORK** | Network comms | SSL pinning, MitM, certificate validation, TLS |
| **MASVS-PLATFORM** | Platform APIs | Intent handling, WebView vulns, IPC, permissions |
| **MASVS-CODE** | Code quality | Injection, code quality, build settings, obfuscation |
| **MASVS-RESILIENCE** | Anti-reversing | Root/jailbreak detection, debugger checks, code tamper detection |

---

## Android Testing Quick Reference

### APK Decompilation Workflow
```bash
# Extract APK
unzip app.apk -d app_root/

# Decompile to Java (preferred)
jadx -d output/ app.apk
# or
cfr classes.dex --outputdir output/

# Disassemble to smali (bytecode)
apktool d app.apk -o app_smali/

# Extract strings/constants
strings classes.dex | grep -i "key\|pass\|secret\|token"
```

### Manifest Analysis Checklist
- [ ] `android:debuggable="true"` — remote debugging enabled
- [ ] Exported Activities/Services/Broadcast Receivers (no protection)
- [ ] High-risk permissions: `INTERNET`, `READ_CONTACTS`, `READ_SMS`, `CAMERA`
- [ ] Intent filters with no data validation
- [ ] Implicit Intents (race condition + hijacking)
- [ ] `android:usesCleartextTraffic="true"` — HTTP allowed
- [ ] `android:backupAgent` — data backup enabled (may bypass encryption)

### Dynamic Analysis Setup
```bash
# Start ADB session
adb devices
adb shell

# Install Frida agent on emulator
adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server -D &  # daemon mode

# Connect Frida from host
frida-ps -U  # list running processes
frida -U com.example.app -l bypass.js
```

---

## iOS Testing Quick Reference

### IPA Analysis
```bash
# Extract IPA (zipped)
unzip app.ipa -d app_root/

# Decompile Mach-O binary
otool -l Payload/app.app/Binary
nm -gU Payload/app.app/Binary  # exported symbols

# Strings and constants
strings Payload/app.app/Binary | grep -i "api\|key\|token"
```

### Dynamic Analysis with Objection
```bash
# Install Frida on iOS (jailbroken device required)
objection -g com.example.app explore

# Inside objection prompt
> ios ui alert_prompt_text  # capture alert text
> ios keychain dump         # keystore dump
> ios plist cat /path       # read plist files
> memory dump all           # heap dump
```

### Frida iOS Hooks
```bash
frida -U -l ios_hooks.js -f com.example.app
```

---

## Common Mobile Vulnerabilities (Bug Bounty Targets)

### 1. Insecure Data Storage
- **Symptom**: Plaintext credentials in Shared Preferences, databases, files
- **Test**: `adb shell cat /data/data/<pkg>/shared_prefs/*.xml`
- **Exploit**: Extract auth tokens, session IDs, PII
- **CVSS**: Medium-High (MASVS-STORAGE-1)

### 2. Hardcoded Secrets
- **Symptom**: API keys, encryption keys in source
- **Test**: `jadx` search for "key=", "secret=", "password="
- **Exploit**: Impersonate app to backend services
- **CVSS**: High (MASVS-STORAGE-2)

### 3. Weak Cryptography
- **Symptom**: MD5, SHA-1, ECB mode, hardcoded IVs
- **Test**: Grep decompiled code for `Cipher.getInstance("AES/ECB")`
- **Exploit**: Decrypt stored data, replay attacks
- **CVSS**: Medium-High (MASVS-CRYPTO-1)

### 4. SSL Pinning Bypass
- **Symptom**: App rejects self-signed certs or custom proxies
- **Test**: Frida hook `SSLContext.init()`, `OkHttp3` pinning
- **Exploit**: Intercept encrypted traffic via MitM
- **CVSS**: High (MASVS-NETWORK-1)

### 5. Improper Session Management
- **Symptom**: Session tokens not invalidated on logout, predictable tokens
- **Test**: Check token lifecycle, re-use after logout
- **Exploit**: Account takeover, session fixation
- **CVSS**: High-Critical (MASVS-AUTH-1)

### 6. WebView Vulnerabilities
- **Symptom**: `setJavaScriptEnabled(true)` + exposed JS bridge
- **Test**: JavaScript injection in WebView, bridge methods
- **Exploit**: RCE via malicious HTML, access to Java APIs
- **CVSS**: High-Critical (MASVS-PLATFORM-1)

### 7. Root/Jailbreak Detection Bypass
- **Symptom**: App refuses to run on rooted device
- **Test**: Frida hook detection functions
- **Exploit**: Run app on controlled environment for reversing
- **CVSS**: Low-Medium (MASVS-RESILIENCE-1)

### 8. Intent/IPC Injection
- **Symptom**: Unvalidated intent parameters, exported services
- **Test**: Send malicious intents, access exported components
- **Exploit**: Arbitrary app behavior, privilege escalation
- **CVSS**: Medium-High (MASVS-PLATFORM-2)

---

## Frida Snippets (Ready-to-Use)

### SSL Pinning Bypass (OkHttp3)
```javascript
Java.perform(() => {
  const OkHttpClient = Java.use("okhttp3.OkHttpClient$Builder");
  OkHttpClient.certificatePinner.overload("okhttp3.CertificatePinner").implementation = function(cp) {
    console.log("[+] Bypassed certificate pinning");
    return this;  // Skip pinning
  };

  const CertificatePinner = Java.use("okhttp3.CertificatePinner");
  CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function(hostname, peerCertificates) {
    console.log(`[+] Pinning check for ${hostname} — BYPASSED`);
  };
});
```

### Root Detection Bypass
```javascript
Java.perform(() => {
  // Hook su binary check
  const ProcessBuilder = Java.use("java.lang.ProcessBuilder");
  ProcessBuilder.$init.overload("[Ljava/lang/String;").implementation = function(cmds) {
    const cmd = cmds[0];
    if (cmd.indexOf("su") !== -1 || cmd.indexOf("build.prop") !== -1) {
      console.log(`[+] Root detection blocked: ${cmd}`);
      // Skip execution or return fake output
    }
    return this.$init(cmds);
  };

  // Hook RootBeer library
  const DetectRootUtils = Java.use("com.scottyab.rootbeer.util.RootBeerNative");
  DetectRootUtils.checkForSU.implementation = function() {
    console.log("[+] RootBeer.checkForSU() bypassed");
    return false;  // Fake: not rooted
  };
});
```

### Biometric Auth Bypass
```javascript
Java.perform(() => {
  const BiometricCallback = Java.use("androidx.biometric.BiometricPrompt$AuthenticationCallback");

  BiometricCallback.onAuthenticationSucceeded.implementation = function(result) {
    console.log("[+] Forcing biometric success");
    return this.onAuthenticationSucceeded(result);
  };

  // Hook at lower level: BiometricManager
  const BiometricManager = Java.use("android.hardware.biometrics.BiometricManager");
  BiometricManager.canAuthenticate.overload("int").implementation = function(authenticators) {
    console.log("[+] canAuthenticate() spoofed to BIOMETRIC_SUCCESS");
    return 0;  // BIOMETRIC_SUCCESS
  };
});
```

### KeyStore Access (Extract Stored Keys)
```javascript
Java.perform(() => {
  const KeyStore = Java.use("java.security.KeyStore");
  const aliases = KeyStore.getInstance("AndroidKeyStore").aliases();

  while (aliases.hasMoreElements()) {
    const alias = aliases.nextElement();
    console.log(`[+] Found KeyStore entry: ${alias}`);

    const key = KeyStore.getInstance("AndroidKeyStore").getKey(alias, null);
    console.log(`    Type: ${key.getAlgorithm()}`);
    console.log(`    Format: ${key.getFormat()}`);
  }
});
```

### Shared Preferences Dump
```javascript
Java.perform(() => {
  const SharedPreferences = Java.use("android.content.SharedPreferences");
  const Map = Java.use("java.util.Map");

  SharedPreferences.getAll.implementation = function() {
    const map = this.getAll();
    const entrySet = map.entrySet();
    const iterator = entrySet.iterator();

    while (iterator.hasNext()) {
      const entry = iterator.next();
      console.log(`[+] SharedPref: ${entry.getKey()} = ${entry.getValue()}`);
    }

    return map;
  };
});
```

### Method Call Tracing
```javascript
Java.perform(() => {
  // Hook all HttpURLConnection connects
  const HttpURLConnection = Java.use("java.net.HttpURLConnection");
  HttpURLConnection.connect.implementation = function() {
    console.log(`[+] HTTP connection to: ${this.getURL()}`);
    console.log(`    Headers: ${this.getHeaderFields()}`);
    return this.connect();
  };
});
```

---

## Tool Integration with Terminator

### Using Frida-MCP Server
```bash
# Frida MCP is pre-loaded in .claude/agents/*.md
# Orchestrator can delegate to reverser/chain agents with:
```
Agent prompt:
```
Use frida-mcp tools to hook [target method]:
- mcp__frida__create_interactive_session(pid)
- mcp__frida__execute_in_session(session_id, "Java.perform(() => { ... })")
```

### Workflow: Mobile Bug Bounty

1. **Scout Phase**: Reconnaissance
   - APK decompile + manifest analysis (apktool, jadx)
   - Strings grep for hardcoded secrets
   - Check AndroidManifest.xml for exported components

2. **Analyst Phase**: Vulnerability Discovery
   - Frida dynamic instrumentation for crypto/auth/storage
   - Root/jailbreak detection bypass
   - SSL pinning inspection
   - WebView + Intent handler analysis

3. **Exploiter Phase**: PoC Development
   - Write Frida hooks for bypasses
   - Craft malicious intents/IPC messages
   - Develop HTTP interception scripts
   - Build end-to-end PoC (e.g., account takeover)

4. **Verifier Phase**: Validation
   - Run PoC against real app instance
   - Verify findings with clean device state
   - Document reproducible steps

5. **Reporter Phase**: Documentation
   - Reference MASVS violation (e.g., MASVS-STORAGE-1)
   - Include CVSS score (mobile scoring differs: AV:L default, SC:C/I:L)
   - Provide remediation code snippets

---

## Mobile CVSS Scoring Rules (Bug Bounty)

- **AV (Attack Vector)**: **Local (L)** for most mobile (device access required)
- **AC (Attack Complexity)**: Low (L) unless jailbreak/root required
- **PR (Privileges Required)**: None unless auth bypass
- **UI (User Interaction)**: Required if user consent needed
- **S (Scope)**: Unchanged unless affects other apps
- **C/I/A (Impact)**: Evaluate per finding

**Example**: Plaintext API key in SharedPrefs
- AV:L, AC:L, PR:N, UI:N, S:U, C:H, I:L, A:N = **CVSS 8.2 (High)**

---

## Resources
- MASTG Web: https://mas.owasp.org/MASTG/
- MASVS Standard: https://mas.owasp.org/MASVS/
- Frida Docs: https://frida.re/docs/
- APKtool: https://ibotpeaches.github.io/Apktool/
- JADX: https://github.com/skylot/jadx
- Objection: https://github.com/sensepost/objection
