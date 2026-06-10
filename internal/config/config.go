// Package config 负责 safe-inspector 的本地配置模型与磁盘读写。
//
// config.yaml 只保存非敏感策略；secrets.enc 通过 internal/secure 加密保存
// SSH/MySQL 密码、私钥 passphrase 和 sudo 密码。
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/RailyW/safe-inspector/internal/safetemplate"
	"github.com/RailyW/safe-inspector/internal/secure"
	"gopkg.in/yaml.v3"
)

const (
	ConfigFileName  = "config.yaml"
	SecretsFileName = "secrets.enc"
	AuditFileName   = "audit.jsonl"

	DefaultTimeoutSeconds = 30
	DefaultMaxOutputBytes = 1024 * 1024

	AdhocRiskLow                 = "low"
	SSHAdhocProfileObservability = "observability-v1"
	DBAdhocProfileReadOnly       = "readonly-v1"
)

// Paths 描述 safe-inspector 在本机使用的所有配置文件路径。
type Paths struct {
	Dir         string `json:"dir"`
	ConfigFile  string `json:"config_file"`
	SecretsFile string `json:"secrets_file"`
	AuditFile   string `json:"audit_file"`
}

// Store 是配置仓库入口，负责把路径解析、YAML/JSON 编解码和加密读写统一起来。
type Store struct {
	Paths Paths
}

// Config 是 config.yaml 的顶层结构，只包含非敏感策略。
type Config struct {
	Version      int                      `json:"version" yaml:"version"`
	CreatedAt    time.Time                `json:"created_at" yaml:"created_at"`
	MasterKey    secure.MasterKeyVerifier `json:"master_key" yaml:"master_key"`
	SSHTargets   []SSHTarget              `json:"ssh_targets" yaml:"ssh_targets"`
	DBTargets    []DBTarget               `json:"db_targets" yaml:"db_targets"`
	SSHTemplates []SSHTemplate            `json:"ssh_templates" yaml:"ssh_templates"`
	DBTemplates  []DBTemplate             `json:"db_templates" yaml:"db_templates"`
}

// SSHTarget 是一台被允许连接的 SSH 机器的非敏感配置。
type SSHTarget struct {
	ID                    string      `json:"id" yaml:"id"`
	Host                  string      `json:"host" yaml:"host"`
	Port                  int         `json:"port" yaml:"port"`
	User                  string      `json:"user" yaml:"user"`
	AuthType              string      `json:"auth_type" yaml:"auth_type"`
	KeyPath               string      `json:"key_path,omitempty" yaml:"key_path,omitempty"`
	AllowSudo             bool        `json:"allow_sudo" yaml:"allow_sudo"`
	DefaultTimeoutSeconds int         `json:"default_timeout_seconds" yaml:"default_timeout_seconds"`
	MaxOutputBytes        int64       `json:"max_output_bytes" yaml:"max_output_bytes"`
	AdhocPolicy           AdhocPolicy `json:"adhoc_policy,omitempty" yaml:"adhoc_policy,omitempty"`
}

// DBTarget 是一个被允许连接的数据库的非敏感配置。
type DBTarget struct {
	ID                    string      `json:"id" yaml:"id"`
	Driver                string      `json:"driver" yaml:"driver"`
	Host                  string      `json:"host" yaml:"host"`
	Port                  int         `json:"port" yaml:"port"`
	Database              string      `json:"database" yaml:"database"`
	Username              string      `json:"username" yaml:"username"`
	DefaultTimeoutSeconds int         `json:"default_timeout_seconds" yaml:"default_timeout_seconds"`
	MaxOutputBytes        int64       `json:"max_output_bytes" yaml:"max_output_bytes"`
	AdhocPolicy           AdhocPolicy `json:"adhoc_policy,omitempty" yaml:"adhoc_policy,omitempty"`
}

// AdhocPolicy 描述某个目标是否允许低风险临时执行。
//
// 该策略是目标级显式授权：旧配置的零值必须保持 disabled，避免升级后
// 自动扩大生产环境访问权限。启用后第一版仅支持 max_risk=low。
type AdhocPolicy struct {
	Enabled bool   `json:"enabled" yaml:"enabled"`
	MaxRisk string `json:"max_risk,omitempty" yaml:"max_risk,omitempty"`
	Profile string `json:"profile,omitempty" yaml:"profile,omitempty"`
}

// SSHTemplate 是某台 SSH 机器允许执行的一条命令模板。
type SSHTemplate struct {
	Name           string                            `json:"name" yaml:"name"`
	Target         string                            `json:"target" yaml:"target"`
	Command        string                            `json:"command" yaml:"command"`
	Params         map[string]safetemplate.ParamRule `json:"params" yaml:"params"`
	Sudo           bool                              `json:"sudo" yaml:"sudo"`
	TimeoutSeconds int                               `json:"timeout_seconds" yaml:"timeout_seconds"`
	MaxOutputBytes int64                             `json:"max_output_bytes" yaml:"max_output_bytes"`
	Description    string                            `json:"description,omitempty" yaml:"description,omitempty"`
}

// DBTemplate 是某个数据库允许执行的一条 SQL 模板。
type DBTemplate struct {
	Name           string                            `json:"name" yaml:"name"`
	Target         string                            `json:"target" yaml:"target"`
	SQL            string                            `json:"sql" yaml:"sql"`
	Kind           string                            `json:"kind" yaml:"kind"`
	Params         map[string]safetemplate.ParamRule `json:"params" yaml:"params"`
	TimeoutSeconds int                               `json:"timeout_seconds" yaml:"timeout_seconds"`
	MaxOutputBytes int64                             `json:"max_output_bytes" yaml:"max_output_bytes"`
	Description    string                            `json:"description,omitempty" yaml:"description,omitempty"`
}

// Secrets 是 secrets.enc 解密后的内存结构，严禁直接输出。
type Secrets struct {
	SSH map[string]SSHSecret `json:"ssh"`
	DB  map[string]DBSecret  `json:"db"`
}

// SSHSecret 保存 SSH 目标的敏感认证信息。
type SSHSecret struct {
	Password      string `json:"password,omitempty"`
	KeyPassphrase string `json:"key_passphrase,omitempty"`
	SudoPassword  string `json:"sudo_password,omitempty"`
}

// DBSecret 保存数据库目标的敏感认证信息。
type DBSecret struct {
	Password string `json:"password,omitempty"`
}

// NewStore 根据显式目录或用户级配置目录创建 Store。
func NewStore(configDir string) (Store, error) {
	dir := configDir
	if dir == "" {
		defaultDir, err := DefaultConfigDir()
		if err != nil {
			return Store{}, err
		}
		dir = defaultDir
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return Store{}, fmt.Errorf("解析配置目录失败: %w", err)
	}
	return Store{Paths: Paths{
		Dir:         abs,
		ConfigFile:  filepath.Join(abs, ConfigFileName),
		SecretsFile: filepath.Join(abs, SecretsFileName),
		AuditFile:   filepath.Join(abs, AuditFileName),
	}}, nil
}

// DefaultConfigDir 返回当前系统用户的 safe-inspector 配置目录。
func DefaultConfigDir() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("获取用户级配置目录失败: %w", err)
	}
	return filepath.Join(dir, "safe-inspector"), nil
}

// Init 创建空配置、空 secret 文件和审计日志文件。
func (s Store) Init(masterKey string) error {
	if _, err := os.Stat(s.Paths.ConfigFile); err == nil {
		return fmt.Errorf("配置文件已存在: %s", s.Paths.ConfigFile)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("检查配置文件失败: %w", err)
	}
	if err := os.MkdirAll(s.Paths.Dir, 0o700); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	verifier, err := secure.NewMasterKeyVerifier(masterKey)
	if err != nil {
		return err
	}
	cfg := Config{
		Version:      1,
		CreatedAt:    time.Now().UTC(),
		MasterKey:    verifier,
		SSHTargets:   []SSHTarget{},
		DBTargets:    []DBTarget{},
		SSHTemplates: []SSHTemplate{},
		DBTemplates:  []DBTemplate{},
	}
	if err := s.SaveConfig(cfg); err != nil {
		return err
	}
	if err := s.SaveSecrets(masterKey, EmptySecrets()); err != nil {
		return err
	}
	file, err := os.OpenFile(s.Paths.AuditFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("创建审计日志失败: %w", err)
	}
	return file.Close()
}

// LoadConfig 从 config.yaml 读取非敏感策略。
func (s Store) LoadConfig() (Config, error) {
	data, err := os.ReadFile(s.Paths.ConfigFile)
	if err != nil {
		return Config{}, fmt.Errorf("读取配置文件失败: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("解析配置文件失败: %w", err)
	}
	return cfg, nil
}

// SaveConfig 将非敏感策略写回 config.yaml。
func (s Store) SaveConfig(cfg Config) error {
	if err := os.MkdirAll(s.Paths.Dir, 0o700); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("编码配置文件失败: %w", err)
	}
	if err := os.WriteFile(s.Paths.ConfigFile, data, 0o600); err != nil {
		return fmt.Errorf("写入配置文件失败: %w", err)
	}
	return nil
}

// LoadSecrets 解密 secrets.enc 并返回内存中的敏感信息结构。
func (s Store) LoadSecrets(masterKey string) (Secrets, error) {
	encrypted, err := os.ReadFile(s.Paths.SecretsFile)
	if err != nil {
		return Secrets{}, fmt.Errorf("读取 secret 文件失败: %w", err)
	}
	plain, err := secure.DecryptSecrets(masterKey, encrypted)
	if err != nil {
		return Secrets{}, err
	}
	var secrets Secrets
	if err := json.Unmarshal(plain, &secrets); err != nil {
		return Secrets{}, fmt.Errorf("解析 secret 文件失败: %w", err)
	}
	secrets.ensureMaps()
	return secrets, nil
}

// SaveSecrets 加密并写入 secrets.enc。
func (s Store) SaveSecrets(masterKey string, secrets Secrets) error {
	secrets.ensureMaps()
	plain, err := json.Marshal(secrets)
	if err != nil {
		return fmt.Errorf("编码 secret 文件失败: %w", err)
	}
	encrypted, err := secure.EncryptSecrets(masterKey, plain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(s.Paths.Dir, 0o700); err != nil {
		return fmt.Errorf("创建配置目录失败: %w", err)
	}
	if err := os.WriteFile(s.Paths.SecretsFile, encrypted, 0o600); err != nil {
		return fmt.Errorf("写入 secret 文件失败: %w", err)
	}
	return nil
}

// FindSSHTarget 根据 ID 查找 SSH 目标。
func (c Config) FindSSHTarget(id string) (SSHTarget, bool) {
	for _, target := range c.SSHTargets {
		if target.ID == id {
			return target, true
		}
	}
	return SSHTarget{}, false
}

// FindDBTarget 根据 ID 查找数据库目标。
func (c Config) FindDBTarget(id string) (DBTarget, bool) {
	for _, target := range c.DBTargets {
		if target.ID == id {
			return target, true
		}
	}
	return DBTarget{}, false
}

// FindSSHTemplate 根据目标 ID 和模板名查找 SSH 模板。
func (c Config) FindSSHTemplate(targetID string, name string) (SSHTemplate, bool) {
	for _, tmpl := range c.SSHTemplates {
		if tmpl.Target == targetID && tmpl.Name == name {
			return tmpl, true
		}
	}
	return SSHTemplate{}, false
}

// FindDBTemplate 根据目标 ID 和模板名查找数据库模板。
func (c Config) FindDBTemplate(targetID string, name string) (DBTemplate, bool) {
	for _, tmpl := range c.DBTemplates {
		if tmpl.Target == targetID && tmpl.Name == name {
			return tmpl, true
		}
	}
	return DBTemplate{}, false
}

// NormalizedAdhocPolicy 返回 SSH 目标的临时执行策略。
//
// 当策略未启用时保持完全关闭；当用户显式启用但省略 max_risk/profile 时，
// 使用 SSH 观测命令的保守默认值。
func (t SSHTarget) NormalizedAdhocPolicy() AdhocPolicy {
	return normalizeAdhocPolicy(t.AdhocPolicy, SSHAdhocProfileObservability)
}

// NormalizedAdhocPolicy 返回 DB 目标的临时执行策略。
//
// 当策略未启用时保持完全关闭；当用户显式启用但省略 max_risk/profile 时，
// 使用 MySQL 只读查询的保守默认值。
func (t DBTarget) NormalizedAdhocPolicy() AdhocPolicy {
	return normalizeAdhocPolicy(t.AdhocPolicy, DBAdhocProfileReadOnly)
}

// normalizeAdhocPolicy 补齐启用状态下的默认风险等级和 profile。
//
// 这里特意不在 disabled 时补默认值，避免配置序列化后看起来像已经放权。
func normalizeAdhocPolicy(policy AdhocPolicy, defaultProfile string) AdhocPolicy {
	if !policy.Enabled {
		return AdhocPolicy{}
	}
	if policy.MaxRisk == "" {
		policy.MaxRisk = AdhocRiskLow
	}
	if policy.Profile == "" {
		policy.Profile = defaultProfile
	}
	return policy
}

// EmptySecrets 返回初始化后的空 secret map，避免调用方处理 nil map。
func EmptySecrets() Secrets {
	return Secrets{SSH: map[string]SSHSecret{}, DB: map[string]DBSecret{}}
}

func (s *Secrets) ensureMaps() {
	if s.SSH == nil {
		s.SSH = map[string]SSHSecret{}
	}
	if s.DB == nil {
		s.DB = map[string]DBSecret{}
	}
}
