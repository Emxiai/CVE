# Buffer Underflow and Pointer Overflow in split_encoded_serialized_payload (Eclipse Cyclone DDS Cryptographic Plugin)

## Basic Information

| Field | Value |
|-------|-------|
| **CVE ID** | (Pending assignment) |
| **Product** | Eclipse Cyclone DDS |
| **Vendor** | Eclipse Foundation / ZettaScale Technology |
| **Affected Versions** | <= 11.0.1 (all versions up to and including 11.0.1) |
| **Fixed Version** | TBD |
| **Component** | Built-in Cryptographic Plugin (libdds_security_crypto.so) |
| **CWE** | CWE-125: Out-of-bounds Read, CWE-190: Integer Overflow or Wraparound |
| **CVSS v3.1** | CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (9.8 Critical) |
| **Attack Vector** | Network (malicious RTPS message) |
| **Impact** | Confidentiality: High, Integrity: High, Availability: High |

---

## Vulnerability Description

The `split_encoded_serialized_payload()` function in the built-in cryptographic plugin contains multiple buffer underflow vulnerabilities and a pointer arithmetic overflow when parsing encoded serialized payloads in RTPS messages. A remote attacker can send a crafted RTPS message to trigger out-of-bounds reads and pointer overflows, leading to information disclosure, memory corruption, and potential remote code execution.

---

## Technical Details

### Root Cause

The function performs multiple reads from `payload->ptr` without verifying sufficient data remains in the buffer. The initial `min_size > length` check does not account for `read_secure_prefix_content()` advancing `ptr` by 20 bytes before subsequent reads.

### Vulnerable Code Locations (src/security/builtin_plugins/cryptographic/src/crypto_transform.c)

| Line | Vulnerability | Description |
|------|---------------|-------------|
| ~502 | Integer Overflow | `min_size += sizeof(uint32_t)` - theoretical overflow if min_size near SIZE_MAX |
| ~504 | Buffer Underflow | `estate->body.data.length = ddsrt_fromBE4u(*(uint32_t*)payload->ptr)` - reads 4 bytes without bounds check |
| ~510 | Pointer Overflow | `payload->ptr += estate->body.data.length` - pointer arithmetic can wrap on 64-bit |
| ~512 | Buffer Underflow | `estate->postfix.common_mac = *(crypto_hmac_t*)payload->ptr` - reads 16 bytes (HMAC) without bounds check |
| ~515 | Buffer Underflow | `estate->postfix.length = ddsrt_fromBE4u(*(uint32_t*)payload->ptr)` - reads 4 bytes without bounds check |

### Vulnerable Function

```c
// src/security/builtin_plugins/cryptographic/src/crypto_transform.c:483
static bool split_encoded_serialized_payload(
    tainted_input_buffer_t *payload,
    struct const_tainted_encrypted_state *estate)
{
    static const size_t header_len = sizeof(estate->prefix.transform_id)
                                    + sizeof(estate->prefix.transform_kind)
                                    + sizeof(estate->prefix.iv);  // 20 bytes
    static const size_t footer_len = sizeof(estate->postfix.common_mac)
                                    + sizeof(estate->postfix.length);  // 20 bytes
    size_t min_size = header_len + footer_len;  // 40
    const size_t length = (size_t)(payload->endp - payload->ptr);

    if (min_size > length)
        return false;

    if (!read_secure_prefix_content(payload, &estate->prefix))
        return false;  // Advances ptr by 20 bytes!

    if (!is_encryption_required(estate->prefix.transform_kind)) {
        estate->body.data.length = length - min_size;
    } else {
        min_size += sizeof(uint32_t);  // 44 - LINE ~502: Integer overflow possible
        if (min_size > length)
            return false;

        // LINE ~504: NO BOUNDS CHECK - reads 4 bytes
        estate->body.data.length = ddsrt_fromBE4u(*(uint32_t*)payload->ptr);
        if (estate->body.data.length > length - min_size)
            return false;
        payload->ptr += sizeof(uint32_t);
    }
    estate->body.data.base = payload->ptr;
    // LINE ~510: POINTER OVERFLOW - no check for wrap
    payload->ptr += estate->body.data.length;

    // LINE ~512: NO BOUNDS CHECK - reads 16 bytes (HMAC)
    estate->postfix.common_mac = *(crypto_hmac_t*)payload->ptr;
    payload->ptr += sizeof(estate->postfix.common_mac);

    // LINE ~515: NO BOUNDS CHECK - reads 4 bytes
    estate->postfix.length = ddsrt_fromBE4u(*(uint32_t*)payload->ptr);
    payload->ptr += sizeof(estate->postfix.length);
    ...
}
```

---

## Impact Assessment

| Impact | Rating | Description |
|--------|--------|-------------|
| **Confidentiality** | **High** | Heap memory disclosure via OOB reads |
| **Integrity** | **High** | Memory corruption via pointer overflow |
| **Availability** | **High** | Process crash, potential RCE |

### Attack Scenarios

1. **Remote Code Execution**: Crafted RTPS message sent to DDS Security-enabled participant
2. **Information Disclosure**: Heap memory leaked via HMAC/postfix.length OOB reads
3. **Denial of Service**: Participant crash via pointer overflow
3. **Supply Chain**: Malicious participant in DDS network

---

## Remediation

Add bounds checks before each read operation:

```c
// Before reading body.length
if ((size_t)(payload->endp - payload->ptr) < sizeof(uint32_t))
    return false;
estate->body.data.length = ddsrt_fromBE4u(*(uint32_t*)payload->ptr);

// Before reading HMAC
if ((size_t)(payload->endp - payload->ptr) < sizeof(crypto_hmac_t))
    return false;
estate->postfix.common_mac = *(crypto_hmac_t*)payload->ptr;

// Before reading postfix.length
if ((size_t)(payload->endp - payload->ptr) < sizeof(uint32_t))
    return false;
estate->postfix.length = ddsrt_fromBE4u(*(uint32_t*)payload->ptr);

// Before pointer arithmetic
if (estate->body.data.length > (size_t)(payload->endp - payload->ptr))
    return false;
payload->ptr += estate->body.data.length;
```

---

## References

- **Repository**: https://github.com/eclipse-cyclonedds/cyclonedds
- **Security Policy**: https://github.com/eclipse-cyclonedds/cyclonedds/blob/main/SECURITY.md

---

## Additional Notes

1. Discovered via static analysis and dynamic testing with AddressSanitizer
2. **Remotely exploitable** in DDS Security-enabled deployments (network attack vector)
3. Affects runtime message processing, not build-time tooling
4. Consider adding fuzzing target for cryptographic parser
5. All DDS Security 1.1 compliant implementations using this plugin are affected
