# Eclipse Mosquitto HTTP API and WebSocket Path Traversal Vulnerability

## Basic Information

| Item | Details |
|------|------|
| **CVE ID** | (Pending assignment) |
| **Product** | Eclipse Mosquitto MQTT Broker |
| **Affected Versions** | 2.0.x - 2.1.x (including 2.1.2) |
| **Fixed Version** | Pending release (recommend upgrading to 2.1.3+) |
| **Components** | HTTP API (`src/http_api.c`), libwebsockets WebSocket (`src/websockets.c`) |
| **Function** | `http__canonical_filename()` |
| **Vulnerability Type** | Path Traversal (CWE-22) |
| **CVSS 3.1** | 6.5 Medium (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) |
| **Attack Vector** | Network (HTTP API port 9883 / WebSocket port 8080) |
| **Privileges Required** | Low (authentication required; default `allow_anonymous false`) |
| **User Interaction** | None |

---

## Vulnerability Description

Eclipse Mosquitto contains a path traversal vulnerability in the file-serving functionality of the HTTP API and libwebsockets WebSocket. The `http__canonical_filename()` function uses `strncmp()` for directory boundary checks and only verifies a prefix match. An attacker can bypass this via a sibling directory with a matching prefix (e.g., `/var/www` vs `/var/www2`) and read arbitrary files outside `http_dir`.

### Root Cause Code

**Files**: `src/http_api.c` (lines 127-130) and `src/websockets.c` (lines 421-424)

```c
// Vulnerable check logic
if(strncmp(http_dir, filename_canonical, strlen(http_dir))){
    /* Requested file isn't within http_dir, deny access */
    mosquitto_FREE(filename_canonical);
    *error_code = MHD_HTTP_NOT_FOUND;
    return NULL;
}
```

**Issue**: `strncmp()` only compares the first `strlen(http_dir)` characters. When `http_dir=/var/www`, a request for `/www2/etc/passwd` resolves to `/var/www2/etc/passwd`. The first 8 characters match, so the check passes.

---

## Scope of Impact

| Attack Surface | Port | Status | Notes |
|--------|------|------|------|
| **MQTT Protocol** | 1883 | **Not affected** | Separate code path; no HTTP file path resolution |
| **HTTP API** | 9883 | **Vulnerable in code; safe under default config** | Config parser automatically appends a trailing `/` to `http_dir` |
| **libwebsockets WebSocket** | 8080 | **Theoretically present; not verified** | `realpath()` strips the trailing `/`, but HTTP file serving did not work as expected |
| **Built-in WebSocket** | 8080 | **Not affected** | Does not serve static files |

---

## Attack Prerequisites

Successful exploitation requires all of the following:

1. **HTTP API or WebSocket file serving enabled**
   ```conf
   listener 9883
   protocol http_api
   http_dir /var/www
   ```

2. **A sibling directory sharing the same path prefix on the filesystem**
   - `http_dir = /var/www`
   - Directory `/var/www2/` exists

3. **Successful authentication** (default `allow_anonymous false`)

---

## Impact Assessment

### Business Impact
- **Data disclosure**: Authenticated users can read arbitrary files under sibling directories that share a prefix with `http_dir`
- **Sensitive files**: SSL certificates, configuration files, system files (`/etc/passwd`, `/etc/shadow`), SSH keys, etc.
- **Attack surface**: Limited to HTTP API/WebSocket ports; authentication required; core MQTT service is unaffected

### CVSS 3.1 Metric Details

| Metric | Value | Notes |
|------|-----|------|
| Attack Vector (AV) | Network (N) | Reachable over the network |
| Attack Complexity (AC) | Low (L) | Low complexity |
| Privileges Required (PR) | Low (L) | Authenticated user required |
| User Interaction (UI) | None (N) | No user interaction required |
| Scope (S) | Unchanged (U) | Does not cross a security boundary |
| Confidentiality (C) | High (H) | Sensitive files can be read |
| Integrity (I) | None (N) | Read-only; no modification |
| Availability (A) | None (N) | No availability impact |

**Base Score: 6.5 (Medium)**

---

## Mitigations

### Temporary Mitigations (Configuration)
1. **Ensure `http_dir` ends with `/`** (already handled automatically in the default configuration path)
2. **Disable unnecessary HTTP API / WebSocket file serving**
   ```conf
   # Comment out or remove
   # listener 9883
   # protocol http_api
   # http_dir /var/www
   ```
3. **Network controls**: Expose the HTTP API port only on trusted networks
4. **Enforce authentication**: Ensure `allow_anonymous false`

### Root Cause Fix (Code)

**File 1**: `src/http_api.c` (approx. lines 127-130)

```c
// Before fix
if(strncmp(http_dir, filename_canonical, strlen(http_dir))){

// After fix
size_t http_dir_len = strlen(http_dir);
if(strncmp(http_dir, filename_canonical, http_dir_len) != 0){
    mosquitto_FREE(filename_canonical);
    *error_code = MHD_HTTP_NOT_FOUND;
    return NULL;
}
// Ensure exact directory match
if(filename_canonical[http_dir_len] != '\0' && filename_canonical[http_dir_len] != DIR_SEP){
    mosquitto_FREE(filename_canonical);
    *error_code = MHD_HTTP_NOT_FOUND;
    return NULL;
}
```

**File 2**: `src/websockets.c` (approx. lines 421-424) — apply the same fix

---

## Detection Guidance

### Version Check
```bash
mosquitto -h | head -1
# mosquitto version 2.1.2
```

### Configuration Check
```bash
grep -A5 "protocol http_api" /etc/mosquitto/mosquitto.conf
grep -A5 "protocol websockets" /etc/mosquitto/mosquitto.conf
```

### Indicators
- Listening on port 9883 (HTTP API) or 8080 (WebSocket)
- `http_dir` directive is configured
- `http_dir` value has no trailing `/` (confirm via config file or code audit)

---

## Appendix: Complete Fix Patch

### src/http_api.c
```diff
--- a/src/http_api.c
+++ b/src/http_api.c
@@ -124,7 +124,13 @@ static char *http__canonical_filename(
 #endif
-	if(strncmp(http_dir, filename_canonical, strlen(http_dir))){
+	size_t http_dir_len = strlen(http_dir);
+	if(strncmp(http_dir, filename_canonical, http_dir_len) != 0){
 		/* Requested file isn't within http_dir, deny access because it's not found. */
 		mosquitto_FREE(filename_canonical);
 		*error_code = MHD_HTTP_NOT_FOUND;
 		return NULL;
 	}
+	/* Ensure exact directory match - not just prefix match */
+	if(filename_canonical[http_dir_len] != '\0' && filename_canonical[http_dir_len] != DIR_SEP){
+		/* Path is a prefix match but not a directory match (e.g., /var/www2) */
+		mosquitto_FREE(filename_canonical);
+		*error_code = MHD_HTTP_NOT_FOUND;
+		return NULL;
+	}
 
 	return filename_canonical;
```

### src/websockets.c
```diff
--- a/src/websockets.c
+++ b/src/websockets.c
@@ -418,7 +418,13 @@ static char *http__canonical_filename(
 #endif
-	if(strncmp(http_dir, filename_canonical, strlen(http_dir))){
+	size_t http_dir_len = strlen(http_dir);
+	if(strncmp(http_dir, filename_canonical, http_dir_len) != 0){
 		/* Requested file isn't within http_dir, deny access. */
 		SAFE_FREE(filename_canonical);
 		lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);
 		return NULL;
 	}
+	/* Ensure exact directory match - not just prefix match */
+	if(filename_canonical[http_dir_len] != '\0' && filename_canonical[http_dir_len] != DIR_SEP){
+		/* Path is a prefix match but not a directory match (e.g., /var/www2) */
+		SAFE_FREE(filename_canonical);
+		lws_return_http_status(wsi, HTTP_STATUS_FORBIDDEN, NULL);
+		return NULL;
+	}
 
 	return filename_canonical;
```
