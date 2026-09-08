# Eclipse Mosquitto HTTP API and WebSocket Path Traversal Vulnerability

## 基本信息

| 项目 | 详情 |
|------|------|
| **CVE ID** | (待分配) |
| **产品** | Eclipse Mosquitto MQTT Broker |
| **影响版本** | 2.0.x - 2.1.x (含 2.1.2) |
| **修复版本** | 待发布 (建议升级至 2.1.3+) |
| **组件** | HTTP API (`src/http_api.c`), libwebsockets WebSocket (`src/websockets.c`) |
| **函数** | `http__canonical_filename()` |
| **漏洞类型** | Path Traversal (CWE-22) |
| **CVSS 3.1** | 6.5 Medium (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N) |
| **攻击向量** | 网络 (HTTP API 端口 9883 / WebSocket 端口 8080) |
| **权限要求** | 低 (需认证，默认 `allow_anonymous false`) |
| **用户交互** | 无 |

---

## 漏洞描述

Eclipse Mosquitto 在 HTTP API 和 libwebsockets WebSocket 的文件服务功能中存在路径遍历漏洞。`http__canonical_filename()` 函数使用 `strncmp()` 进行目录边界检查，仅验证前缀匹配，攻击者可通过目录前缀绕过（如 `/var/www` vs `/var/www2`）读取 `http_dir` 之外的任意文件。

### 根因代码

**文件**: `src/http_api.c` (行 127-130) 和 `src/websockets.c` (行 421-424)

```c
// 易受攻击的检查逻辑
if(strncmp(http_dir, filename_canonical, strlen(http_dir))){
    /* Requested file isn't within http_dir, deny access */
    mosquitto_FREE(filename_canonical);
    *error_code = MHD_HTTP_NOT_FOUND;
    return NULL;
}
```

**问题**: `strncmp()` 仅比较前 `strlen(http_dir)` 个字符。当 `http_dir=/var/www` 时，请求 `/www2/etc/passwd` 解析为 `/var/www2/etc/passwd`，前 8 字符匹配，检查通过。

---

## 影响范围

| 攻击面 | 端口 | 状态 | 说明 |
|--------|------|------|------|
| **MQTT 协议** | 1883 | **不受影响** | 独立代码路径，不涉及 HTTP 文件解析 |
| **HTTP API** | 9883 | **代码有缺陷，默认配置安全** | 配置解析器自动给 `http_dir` 补齐尾部 `/` |
| **libwebsockets WebSocket** | 8080 | **理论存在，未验证** | `realpath()` 移除尾部 `/`，但 HTTP 文件服务未正常工作 |
| **内置 WebSocket** | 8080 | **不受影响** | 不提供静态文件服务 |

---

## 攻击前提

要成功利用此漏洞，需同时满足：

1. **启用 HTTP API 或 WebSocket 文件服务**
   ```conf
   listener 9883
   protocol http_api
   http_dir /var/www
   ```

2. **文件系统存在同级前缀目录**
   - `http_dir = /var/www`
   - 存在 `/var/www2/` 目录

3. **认证通过** (默认 `allow_anonymous false`)

---

---

## 影响评估

### 业务影响
- **数据泄露**: 认证用户可读取服务器文件系统中 `http_dir` 同级目录下的任意文件
- **敏感文件**: SSL 证书、配置文件、系统文件 (`/etc/passwd`, `/etc/shadow`)、SSH 密钥等
- **攻击面**: 仅限 HTTP API/WebSocket 端口，需认证，不影响核心 MQTT 服务

### CVSS 3.1 评分详情

| 指标 | 值 | 说明 |
|------|-----|------|
| Attack Vector (AV) | Network (N) | 网络可达 |
| Attack Complexity (AC) | Low (L) | 低复杂度 |
| Privileges Required (PR) | Low (L) | 需认证用户 |
| User Interaction (UI) | None (N) | 无需用户交互 |
| Scope (S) | Unchanged (U) | 未跨越权限边界 |
| Confidentiality (C) | High (H) | 可读取敏感文件 |
| Integrity (I) | None (N) | 仅读取，无修改 |
| Availability (A) | None (N) | 无可用性影响 |

**Base Score: 6.5 (Medium)**

---

## 缓解措施

### 临时缓解 (配置层面)
1. **确保 `http_dir` 以 `/` 结尾** (默认配置已自动处理)
2. **禁用不必要的 HTTP API/WebSocket 文件服务**
   ```conf
   # 注释掉或移除
   # listener 9883
   # protocol http_api
   # http_dir /var/www
   ```
3. **网络层限制**: 仅在可信网络暴露 HTTP API 端口
4. **强制认证**: 确保 `allow_anonymous false`

### 根因修复 (代码层面)

**文件 1**: `src/http_api.c` (约行 127-130)

```c
// 修复前
if(strncmp(http_dir, filename_canonical, strlen(http_dir))){

// 修复后
size_t http_dir_len = strlen(http_dir);
if(strncmp(http_dir, filename_canonical, http_dir_len) != 0){
    mosquitto_FREE(filename_canonical);
    *error_code = MHD_HTTP_NOT_FOUND;
    return NULL;
}
// 确保精确目录匹配
if(filename_canonical[http_dir_len] != '\0' && filename_canonical[http_dir_len] != DIR_SEP){
    mosquitto_FREE(filename_canonical);
    *error_code = MHD_HTTP_NOT_FOUND;
    return NULL;
}
```

**文件 2**: `src/websockets.c` (约行 421-424) - 同理修复

---

## 检测指引

### 版本检测
```bash
mosquitto -h | head -1
# mosquitto version 2.1.2
```

### 配置检测
```bash
grep -A5 "protocol http_api" /etc/mosquitto/mosquitto.conf
grep -A5 "protocol websockets" /etc/mosquitto/mosquitto.conf
```

### 特征检测
- 监听端口 9883 (HTTP API) 或 8080 (WebSocket)
- 配置了 `http_dir` 指令
- `http_dir` 值无尾部 `/` (可通过配置文件或代码审计确认)

---

## 附录: 完整修复补丁

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
