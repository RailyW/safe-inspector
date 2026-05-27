package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/RailyW/safe-inspector/internal/audit"
	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/secure"
)

func loadConfigAndVerifyMaster(store config.Store, stdout io.Writer) (config.Config, string, error) {
	cfg, err := store.LoadConfig()
	if err != nil {
		return config.Config{}, "", err
	}
	masterKey, err := promptMasterKey(stdout, "请输入 safe-inspector 主秘钥以确认策略变更: ")
	if err != nil {
		return config.Config{}, "", err
	}
	if !cfg.MasterKey.Verify(masterKey) {
		return config.Config{}, "", fmt.Errorf("主秘钥校验失败")
	}
	return cfg, masterKey, nil
}

func loadExecutionSecrets(store config.Store) (config.Secrets, string, error) {
	masterKey := os.Getenv(secure.EnvMasterKey)
	if masterKey == "" {
		return config.Secrets{}, "", fmt.Errorf("缺少环境变量 %s，无法内部解密认证信息", secure.EnvMasterKey)
	}
	secrets, err := store.LoadSecrets(masterKey)
	if err != nil {
		return config.Secrets{}, "", err
	}
	return secrets, masterKey, nil
}

func writeAudit(store config.Store, event audit.Event) string {
	id, err := audit.Writer{Path: store.Paths.AuditFile}.Write(event)
	if err != nil {
		return ""
	}
	return id
}

func defaultTimeoutSeconds(value int) int {
	if value <= 0 {
		return config.DefaultTimeoutSeconds
	}
	return value
}

func defaultMaxOutputBytes(value int64) int64 {
	if value <= 0 {
		return config.DefaultMaxOutputBytes
	}
	return value
}
