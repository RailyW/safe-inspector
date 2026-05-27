# internal/secure

`internal/secure` 负责 safe-inspector 的本地敏感信息加密、解密与主秘钥校验。

## 包含文件

- `secure.go`：定义 `EncryptSecrets`、`DecryptSecrets`、`MasterKeyVerifier` 等加密接口。
- `secure_test.go`：覆盖加密往返、错误主秘钥拒绝、主秘钥校验器行为。

## 安全说明

- 认证信息使用 `SAFE_INSPECTOR_MASTER_KEY` 经 Argon2id 派生 AES-256-GCM 密钥后加密。
- 本模块不理解 SSH、数据库或模板策略，只处理字节级密文，避免上层业务逻辑污染加密边界。
- 错误信息不会包含主秘钥、密码、passphrase、sudo 密码或解密后的明文。
