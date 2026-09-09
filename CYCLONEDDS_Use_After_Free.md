# Heap Use-After-Free in Recursive #include Handling (Eclipse Cyclone DDS IDL Compiler)

## Basic Information

| Field | Value |
|-------|-------|
| **CVE ID** | (Pending assignment) |
| **Product** | Eclipse Cyclone DDS |
| **Vendor** | Eclipse Foundation / ZettaScale Technology |
| **Affected Versions** | <= 11.0.1 (all versions up to and including 11.0.1) |
| **Fixed Version** | TBD |
| **Component** | IDL Compiler (idlc) - Preprocessor (idlpp) |
| **CWE** | CWE-416: Use After Free |
| **CVSS v3.1** | CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H (7.7 High) |
| **Attack Vector** | Local (requires processing malicious IDL file) |
| **Impact** | Integrity: High, Availability: High |

---

## Vulnerability Description

The IDL compiler's preprocessor contains a heap use-after-free vulnerability when processing recursive #include directives. When a file includes itself (directly or through a chain of includes), the file handle and associated memory are freed while still being referenced by the recursive call stack, leading to memory corruption.

---

## Technical Details

### Root Cause

The preprocessor does not track currently processing files to prevent recursive inclusion. When open_include() calls open_file() which calls norm_path(), memory is allocated for the normalized path. During recursive processing, the FILEINFO structure is freed but the call stack still holds references to it. When error reporting (cfatal()) accesses the freed filename string, a use-after-free occurs.

### Vulnerable Code Path

directive.c:325 do_include()
    -> system.c:3364 open_include()
        -> system.c:3548 open_file()
            -> system.c:2637 norm_path()  // Allocates memory for normalized path
            -> Allocates FILEINFO struct
        -> Recursive call to open_include() for same file
            -> Same file opened again, memory freed in cleanup
            -> Call stack still references freed FILEINFO
            -> cfatal() accesses freed filename -> USE-AFTER-FREE

### Affected Files

| File | Function | Line |
|------|----------|------|
| src/tools/idlc/idlpp/src/directive.c | do_include() | ~325 |
| src/tools/idlc/idlpp/src/system.c | open_include() | ~3364 |
| src/tools/idlc/idlpp/src/system.c | open_file() | ~3548 |
| src/tools/idlc/idlpp/src/system.c | norm_path() | ~2637 |
| src/tools/idlc/idlpp/src/support.c | cfatal() | ~2635 |

---

## Impact Assessment

| Impact | Rating | Description |
|--------|--------|-------------|
| **Confidentiality** | None | No direct info leak demonstrated |
| **Integrity** | **High** | Heap memory corruption |
| **Availability** | **High** | Process crash (DoS), potential RCE |

### Real-World Impact Scenarios

1. **CI/CD Pipeline Crash**: Malicious IDL causes build failure
2. **Arbitrary Code Execution**: With heap grooming, use-after-free could lead to RCE
3. **Denial of Service**: Build systems processing untrusted IDL files crash

---

## Remediation

### Fix 1: Recursive Include Detection

Track currently processing files in open_file():

```c
// In open_file() before processing
static bool is_file_being_processed(const char *fullname) {
    for (FILEINFO *f = infile; f; f = f->parent) {
        if (f->fname && strcmp(f->fname, fullname) == 0)
            return true;
    }
    return false;
}

if (is_file_being_processed(fullname)) {
    // Recursive include detected - reject gracefully
    return NULL;
}
```

### Fix 2: Proper Memory Lifetime Management

Ensure FILEINFO structures are not freed until all references are released, or use reference counting.

---

## References

- **Repository**: https://github.com/eclipse-cyclonedds/cyclonedds
- **Security Policy**: https://github.com/eclipse-cyclonedds/cyclonedds/blob/main/SECURITY.md

---

## Additional Notes

1. Discovered via dynamic testing with AddressSanitizer (built into the Cyclone DDS build)
2. Affects build-time tooling (IDL compiler), not runtime
3. Self-referential includes are a common pattern in malicious inputs
4. Consider adding include depth limit as additional defense
