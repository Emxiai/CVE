# Path Traversal in #include Directive (Eclipse Cyclone DDS IDL Compiler)

## Basic Information

| Field | Value |
|-------|-------|
| **CVE ID** | (Pending assignment) |
| **Product** | Eclipse Cyclone DDS |
| **Vendor** | Eclipse Foundation / ZettaScale Technology |
| **Affected Versions** | <= 11.0.1 (all versions up to and including 11.0.1) |
| **Fixed Version** | TBD |
| **Component** | IDL Compiler (idlc) - Preprocessor (idlpp) |
| **CWE** | CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') |
| **CVSS v3.1** | CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N (6.2 Medium) |
| **Attack Vector** | Local (requires processing malicious IDL file) |
| **Impact** | Confidentiality: High (arbitrary file read) |

---

## Vulnerability Description

The IDL compiler (idlc) in Eclipse Cyclone DDS does not properly validate file paths in #include directives. An attacker who can control the content of an IDL file processed by the compiler can use directory traversal sequences (e.g., #include "../../../etc/passwd") to escape the intended include search paths and read arbitrary files on the filesystem.

---

## Technical Details

### Root Cause

The preprocessor resolves include paths relative to the current file or include search directories (inc_dirp) but lacks **containment validation** to ensure the resolved path remains within allowed directories.

The vulnerable code path:
1. #include directive parsed in src/tools/idlc/idlpp/src/directive.c -> do_include()
2. Calls open_include() in src/tools/idlc/idlpp/src/system.c:3364
3. Which calls open_file() -> norm_path() to normalize the path
4. norm_path() resolves ../ sequences but **does not verify** the result stays within allowed include directories
5. File is opened and contents included in preprocessor output

### Affected Files

| File | Function | Line |
|------|----------|------|
| src/tools/idlc/idlpp/src/directive.c | do_include() | ~325 |
| src/tools/idlc/idlpp/src/system.c | open_include() | ~3364 |
| src/tools/idlc/idlpp/src/system.c | open_file() | ~3548 |
| src/tools/idlc/idlpp/src/system.c | norm_path() | ~2637 |
| src/tools/idlc/libidl/src/file.c | idl_normalize_path() | ~229 |

---

## Impact Assessment

| Impact | Rating | Description |
|--------|--------|-------------|
| **Confidentiality** | **High** | Arbitrary file read on build system/CI/CD pipeline |
| **Integrity** | None | No write capability demonstrated |
| **Availability** | None | No crash or DoS |

### Real-World Impact Scenarios

1. **CI/CD Pipeline Compromise**: Malicious IDL in dependency repository reads /etc/passwd, SSH keys (~/.ssh/id_rsa), AWS credentials (~/.aws/credentials), .env files
2. **Supply Chain Attack**: Compromised third-party IDL definitions exfiltrate build server secrets
3. **Developer Machine**: Local builds process untrusted IDL files from git repositories

---

## Remediation

### Immediate Fix

Add path containment validation in open_include() and open_file():

```c
// In open_include() / open_file() after norm_path()
static bool is_path_allowed(const char *resolved_path) {
    // Check against inc_dirp (include search directories)
    // Return false if path escapes allowed directories
}

if (!is_path_allowed(fullname)) {
    return NULL;  // Reject include
}
```

### Defense in Depth

Also add validation in idl_normalize_path() (src/tools/idlc/libidl/src/file.c:229):

```c
// After path normalization
if (!idl_is_path_allowed(normpath)) {
    ret = IDL_RETCODE_BAD_PARAMETER;
    goto err_norm;
}
```

---

## References

- **Repository**: https://github.com/eclipse-cyclonedds/cyclonedds
- **Security Policy**: https://github.com/eclipse-cyclonedds/cyclonedds/blob/main/SECURITY.md

---

## Additional Notes

1. Discovered via static analysis and dynamic testing with AddressSanitizer
2. Affects build-time tooling (IDL compiler), not runtime
3. Requires attacker to control IDL file content (realistic in CI/CD, package builds)
4. Consider adding fuzzing target for IDL compiler include handling
