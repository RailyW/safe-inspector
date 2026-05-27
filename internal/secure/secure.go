// Package secure 负责 safe-inspector 的本地 secret 加密与主秘钥校验。
//
// 本包只处理字节级加密，不理解 SSH、MySQL 或业务配置含义；这样可以确保
// 认证信息的存储格式和上层策略逻辑解耦，便于未来替换密钥来源或加密参数。
package secure

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

	"golang.org/x/crypto/argon2"
)

const (
	// EnvMasterKey 是执行命令时用于内部解密 AUTH 信息的环境变量名称。
	// CLI 不会把该值打印到输出、审计或错误信息中。
	EnvMasterKey = "SAFE_INSPECTOR_MASTER_KEY"

	payloadVersion = 1
	kdfName        = "argon2id"
	kdfTime        = uint32(1)
	kdfMemory      = uint32(32 * 1024)
	kdfThreads     = uint8(4)
	kdfKeyLen      = uint32(32)
	saltSize       = 16
)

// EncryptedPayload 是 secrets.enc 的 JSON 外壳。
// Salt/Nonce/Ciphertext 均使用 base64，避免二进制内容在跨平台读写时损坏。
type EncryptedPayload struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// MasterKeyVerifier 是 config.yaml 中保存的主秘钥校验材料。
// 它只保存 Argon2id 派生结果，不保存主秘钥明文；校验使用常量时间比较。
type MasterKeyVerifier struct {
	KDF  string `json:"kdf" yaml:"kdf"`
	Salt string `json:"salt" yaml:"salt"`
	Hash string `json:"hash" yaml:"hash"`
}

// EncryptSecrets 使用主秘钥派生 AES-256-GCM 密钥，并加密传入的 secret JSON。
// 返回值是可直接写入 secrets.enc 的 JSON 字节。
func EncryptSecrets(masterKey string, plain []byte) ([]byte, error) {
	if masterKey == "" {
		return nil, errors.New("主秘钥不能为空")
	}

	salt, err := randomBytes(saltSize)
	if err != nil {
		return nil, fmt.Errorf("生成加密盐失败: %w", err)
	}
	key := deriveKey(masterKey, salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("初始化 AES 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 GCM 失败: %w", err)
	}
	nonce, err := randomBytes(gcm.NonceSize())
	if err != nil {
		return nil, fmt.Errorf("生成 nonce 失败: %w", err)
	}

	payload := EncryptedPayload{
		Version:    payloadVersion,
		KDF:        kdfName,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(gcm.Seal(nil, nonce, plain, nil)),
	}
	return json.MarshalIndent(payload, "", "  ")
}

// DecryptSecrets 使用主秘钥解开 secrets.enc 内容。
// 认证失败时仅返回通用错误，不把任何密文或明文写入错误文本。
func DecryptSecrets(masterKey string, encrypted []byte) ([]byte, error) {
	if masterKey == "" {
		return nil, errors.New("主秘钥不能为空")
	}

	var payload EncryptedPayload
	if err := json.Unmarshal(encrypted, &payload); err != nil {
		return nil, fmt.Errorf("解析加密文件失败: %w", err)
	}
	if payload.Version != payloadVersion || payload.KDF != kdfName {
		return nil, errors.New("加密文件版本或 KDF 不受支持")
	}

	salt, err := base64.StdEncoding.DecodeString(payload.Salt)
	if err != nil {
		return nil, errors.New("加密文件 salt 格式无效")
	}
	nonce, err := base64.StdEncoding.DecodeString(payload.Nonce)
	if err != nil {
		return nil, errors.New("加密文件 nonce 格式无效")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(payload.Ciphertext)
	if err != nil {
		return nil, errors.New("加密文件 ciphertext 格式无效")
	}

	key := deriveKey(masterKey, salt)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("初始化 AES 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("初始化 GCM 失败: %w", err)
	}
	if len(nonce) != gcm.NonceSize() {
		return nil, errors.New("加密文件 nonce 长度无效")
	}

	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.New("解密失败，请检查主秘钥或加密文件")
	}
	return plain, nil
}

// NewMasterKeyVerifier 生成可写入 config.yaml 的主秘钥校验器。
// 它用于策略变更命令确认“真人输入了正确主秘钥”，不负责解密 secret。
func NewMasterKeyVerifier(masterKey string) (MasterKeyVerifier, error) {
	if masterKey == "" {
		return MasterKeyVerifier{}, errors.New("主秘钥不能为空")
	}
	salt, err := randomBytes(saltSize)
	if err != nil {
		return MasterKeyVerifier{}, fmt.Errorf("生成校验盐失败: %w", err)
	}
	hash := deriveKey(masterKey, salt)
	return MasterKeyVerifier{
		KDF:  kdfName,
		Salt: base64.StdEncoding.EncodeToString(salt),
		Hash: base64.StdEncoding.EncodeToString(hash),
	}, nil
}

// Verify 使用常量时间比较校验候选主秘钥是否匹配初始化时的主秘钥。
func (v MasterKeyVerifier) Verify(masterKey string) bool {
	if masterKey == "" || v.KDF != kdfName {
		return false
	}
	salt, err := base64.StdEncoding.DecodeString(v.Salt)
	if err != nil {
		return false
	}
	want, err := base64.StdEncoding.DecodeString(v.Hash)
	if err != nil {
		return false
	}
	got := deriveKey(masterKey, salt)
	return len(want) == len(got) && subtle.ConstantTimeCompare(want, got) == 1
}

// EmptyEncryptedPayload 返回一个可写入 secrets.enc 的空 secret 文件。
func EmptyEncryptedPayload(masterKey string) ([]byte, error) {
	return EncryptSecrets(masterKey, []byte(`{"ssh":{},"db":{}}`))
}

func deriveKey(masterKey string, salt []byte) []byte {
	return argon2.IDKey([]byte(masterKey), salt, kdfTime, kdfMemory, kdfThreads, kdfKeyLen)
}

func randomBytes(size int) ([]byte, error) {
	buf := bytes.Repeat([]byte{0}, size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}
	return buf, nil
}
