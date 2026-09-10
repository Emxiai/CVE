# MuJoCo MJCF/XML Include Path Traversal

### Basic Information

| Field | Value |
|-------|-------|
| **CVE ID** | (to be assigned) |
| **Product** | MuJoCo (Multi-Joint dynamics with Contact) |
| **Vendor** | Google DeepMind |
| **Affected Versions** | All versions supporting `<include>` element (≤ 3.2.x) |
| **Fixed Version** | Pending (3.3.0+) |
| **Vulnerability Type** | Path Traversal (CWE-22) |
| **CVSS 3.1 Score** | 7.5 (High) - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| **Discovery Date** | 2026-09-10 |
| **Reported Date** | 2026-09-10 |
| **Public Disclosure** | TBD (coordinated with vendor) |

---

### Vulnerability Description

**Summary**: The MJCF/XML model format in MuJoCo supports an `<include file="..."/>` element for modular model composition. The path resolution logic fails to validate that included file paths remain within the model directory, allowing attackers to read arbitrary files on the host filesystem via absolute paths (e.g., `/etc/passwd`) or relative paths with excessive directory traversal sequences (e.g., `../../../etc/passwd`).

**Impact**: An attacker who can supply a malicious MJCF/XML model file to an application using MuJoCo can achieve arbitrary file read with the privileges of the MuJoCo process. This includes sensitive files such as `/etc/passwd`, `/proc/self/environ` (exposing environment variables/API keys), SSH keys, AWS credentials, and application configuration files.

**Attack Vector**: Network or Local - Applications that accept user-uploaded MJCF models, load models from untrusted sources, or process third-party model repositories are vulnerable.

---

### Technical Details

#### Root Cause Analysis

The vulnerability exists in the include file path resolution chain:

1. **`src/xml/xml.cc:183-210` - `IncludeXML()` function**
   - Parses `<include file="..."/>` element
   - Calls `mjXUtil::ReadAttrFile()` → `ResolveFilePath()`
   - No validation of absolute paths or path traversal sequences

2. **`src/xml/xml_util.cc:84-90` - `ResolveFilePath()` function**
   ```cpp
   FilePath ResolveFilePath(XMLElement* e, const FilePath& filename, 
                            const FilePath& dir, const mjVFS* vfs) {
       if (filename.IsAbs()) { return filename; }  // VULNERABLE: returns absolute path as-is
       // ...
   }
   ```

3. **`src/user/user_util.cc:472` - `FilePath::Combine()`**
   ```cpp
   static std::string Combine(const std::string& s1, const std::string& s2) {
       if (!AbsPrefix(s2).empty()) { return s2; }  // VULNERABLE: absolute path bypasses base dir
       // ...
   }
   ```

4. **`src/user/user_util.cc:500-540` - `FilePath::PathReduce()`**
   - Fails to fully resolve `..` components when they exceed the path depth
   - Example: `models/../../../etc/passwd` → `models/../../../etc/passwd` (not resolved to `/etc/passwd`)

5. **`src/user/user_vfs.cc:40` - `OpenFile()` (default file provider)**
   ```cpp
   int OpenFile(const char* filename, mjResource* resource) {
       struct stat file_stat;
       if (stat(filename, &file_stat) == 0) {  // Kernel resolves ../
           // File read proceeds
       }
   }
   ```

#### Attack Vectors

| Vector | Example Payload | Result |
|--------|-----------------|--------|
| Absolute Path | `<include file="/etc/passwd"/>` | Direct read of any absolute path |
| Relative Traversal | `<include file="../../../etc/passwd"/>` | Directory traversal via `..` |
| Windows Path | `<include file="C:\\Windows\\System32\\drivers\\etc\\hosts"/>` | Windows absolute path |
| Nested Includes | `<include file="subdir/../../../etc/passwd"/>` | Traversal through nested includes |

### Affected Code Locations

| File | Function | Lines | Issue |
|------|----------|-------|-------|
| `src/xml/xml.cc` | `IncludeXML()` | 183-210 | No path validation |
| `src/xml/xml_util.cc` | `ResolveFilePath()` | 84-90 | Returns absolute paths |
| `src/user/user_util.cc` | `FilePath::Combine()` | 470-475 | Bypasses base directory |
| `src/user/user_util.cc` | `FilePath::PathReduce()` | 500-540 | Incomplete `..` resolution |
| `src/user/user_vfs.cc` | `OpenFile()` | 40-50 | Kernel resolves `..` |

---

### Affected Entry Points

- `mj_loadXML()` - C API
- `mj_parseXML()` - C API  
- `MjModel.from_xml_path()` - Python API
- `MjModel.from_xml_string()` - Python API
- `MjSpec.from_string()` - Python API
- `MjSpec.from_file()` - Python API

---

### Remediation

#### Recommended Fix (Option 1: Path Validation)

```cpp
// In src/xml/xml.cc IncludeXML() function
auto file_attr = mjXUtil::ReadAttrFile(elem, "file", vfs, reader.ModelFileDir(), true);
FilePath filename = file_attr.value();

// SECURITY FIX: Reject absolute paths
if (filename.IsAbs()) {
    throw mjXError(elem, "Include file attribute cannot be an absolute path");
}

// SECURITY FIX: Resolve and validate path stays within model directory
FilePath fullname = dir + filename;
std::string resolved_path = fullname.Str();

// TODO: Use realpath() to verify resolved_path is within model directory
// char* real = realpath(resolved_path.c_str(), nullptr);
// char* model_real = realpath(reader.ModelFileDir().c_str(), nullptr);
// if (strncmp(real, model_real, strlen(model_real)) != 0) {
//     throw mjXError(elem, "Include file path escapes model directory");
// }
// free(real); free(model_real);
```

#### Defense-in-Depth (Option 2: openat-based File Access)

```cpp
// In src/user/user_vfs.cc OpenFile()
int OpenFile(const char* filename, mjResource* resource) {
    // Open base directory with O_DIRECTORY
    int base_fd = open(model_base_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (base_fd < 0) return 0;
    
    // Use openat to prevent path traversal
    int fd = openat(base_fd, filename, O_RDONLY | O_CLOEXEC);
    close(base_fd);
    
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) == 0) {
            // Read file contents via fd
            close(fd);
            return 1;
        }
        close(fd);
    }
    return 0;
}
```

#### Configuration Option (Option 3: Compiler Security Flags)

```cpp
// In include/mujoco/mjspec.h
typedef struct mjsCompiler_ {
    // ... existing fields
    mjtBool allowincludes;      // Default: true
    mjtBool restrictincludes;   // Default: false - limit to model dir
} mjsCompiler;
```

---

### References

1. **MuJoCo Repository**: https://github.com/google-deepmind/mujoco
2. **Security Policy**: https://github.com/google-deepmind/mujoco/blob/main/SECURITY.md
3. **CWE-22**: https://cwe.mitre.org/data/definitions/22.html
4. **OWASP Path Traversal**: https://owasp.org/www-community/attacks/Path_Traversal
