# Security Policy: Vaishnavi Antivirus Suite

## Threat Model & Security Boundaries

`vaishnavi-antivirus` is a security diagnostic and malware detection suite. Because it processes untrusted and potentially malicious files, the following defensive safeguards are enforced:

1. **Path Traversal Protection:** All quarantine copy operations strip directory components and restrict target paths to sanitized filenames within the dedicated quarantine vault.
2. **Resource Exhaustion Defense:** Directory traversal limits (`--max-files`, default 1000) prevent infinite recursion, symlink loops, or denial-of-service against the host scanning engine.
3. **Safe File Probing:** Signature checks compute hashes in buffered chunks (8192 bytes) without loading entire unknown binaries into memory.
4. **Unprivileged Container Execution:** The production container environment runs under an unprivileged user (UID 10001 `vaishnavi`) without root or host-level capabilities.

## Safe Malware Testing

When verifying scanner performance, use industry-standard benign test files such as the standard EICAR test string:
```text
X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*
```
Do not execute live malware samples directly on production systems.

## Reporting Vulnerabilities

If you discover a vulnerability or security bypass in `vaishnavi-antivirus`:
1. Do not file public GitHub issues.
2. Email security advisories to: `kanakprabhakar72@gmail.com`.
3. Include a description of the issue, affected version, and reproduction steps.
4. Maintainers will acknowledge within 48 hours and work on remediation.
