// Package sshclient 封装 SSH 连接与一次性命令执行。
//
// 本包不决定命令是否安全，只执行上层已经通过模板与策略校验的命令；
// sudo 只在调用方显式传入 sudo=true 时使用，并通过 stdin 写入 sudo 密码。
package sshclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/safetemplate"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Result 是 SSH 命令的一次性执行结果。
type Result struct {
	Stdout    string `json:"stdout"`
	Stderr    string `json:"stderr"`
	ExitCode  int    `json:"exit_code"`
	Truncated bool   `json:"truncated"`
}

// Execute 连接目标机器并执行命令。调用方负责传入已经渲染后的安全命令。
func Execute(ctx context.Context, target config.SSHTarget, secret config.SSHSecret, command string, useSudo bool, timeout time.Duration, maxOutputBytes int64) (Result, error) {
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultTimeoutSeconds) * time.Second
	}
	if maxOutputBytes <= 0 {
		maxOutputBytes = config.DefaultMaxOutputBytes
	}

	clientConfig, err := buildClientConfig(target, secret)
	if err != nil {
		return Result{}, err
	}
	address := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type dialResult struct {
		client *ssh.Client
		err    error
	}
	dialDone := make(chan dialResult, 1)
	go func() {
		client, err := ssh.Dial("tcp", address, clientConfig)
		dialDone <- dialResult{client: client, err: err}
	}()

	var client *ssh.Client
	select {
	case <-ctx.Done():
		return Result{}, errors.New("SSH 连接超时")
	case result := <-dialDone:
		if result.err != nil {
			return Result{}, fmt.Errorf("SSH 连接失败: %w", result.err)
		}
		client = result.client
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		return Result{}, fmt.Errorf("创建 SSH session 失败: %w", err)
	}
	defer session.Close()

	stdout := &limitedBuffer{limit: maxOutputBytes / 2}
	stderr := &limitedBuffer{limit: maxOutputBytes / 2}
	session.Stdout = stdout
	session.Stderr = stderr

	execCommand := command
	if useSudo {
		if secret.SudoPassword == "" {
			return Result{}, errors.New("模板要求 sudo，但未配置 sudo 密码")
		}
		execCommand = "sudo -S -p '' sh -c " + shellQuoteForSudo(command)
		stdin, err := session.StdinPipe()
		if err != nil {
			return Result{}, fmt.Errorf("创建 sudo stdin 失败: %w", err)
		}
		go func() {
			defer stdin.Close()
			_, _ = stdin.Write([]byte(secret.SudoPassword + "\n"))
		}()
	}

	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run(execCommand)
	}()
	select {
	case <-ctx.Done():
		_ = client.Close()
		return Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: -1, Truncated: stdout.truncated || stderr.truncated}, errors.New("SSH 命令执行超时")
	case err := <-runDone:
		result := Result{Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: exitCode(err), Truncated: stdout.truncated || stderr.truncated}
		if err != nil {
			return result, fmt.Errorf("SSH 命令执行失败: %w", err)
		}
		return result, nil
	}
}

func buildClientConfig(target config.SSHTarget, secret config.SSHSecret) (*ssh.ClientConfig, error) {
	auth, err := buildAuthMethod(target, secret)
	if err != nil {
		return nil, err
	}
	callback, err := hostKeyCallback()
	if err != nil {
		return nil, err
	}
	return &ssh.ClientConfig{
		User:            target.User,
		Auth:            []ssh.AuthMethod{auth},
		HostKeyCallback: callback,
		Timeout:         time.Duration(target.DefaultTimeoutSeconds) * time.Second,
	}, nil
}

func buildAuthMethod(target config.SSHTarget, secret config.SSHSecret) (ssh.AuthMethod, error) {
	switch target.AuthType {
	case "password":
		if secret.Password == "" {
			return nil, errors.New("SSH password 认证缺少密码")
		}
		return ssh.Password(secret.Password), nil
	case "key":
		if target.KeyPath == "" {
			return nil, errors.New("SSH key 认证缺少 key_path")
		}
		keyBytes, err := os.ReadFile(target.KeyPath)
		if err != nil {
			return nil, fmt.Errorf("读取 SSH 私钥失败: %w", err)
		}
		var signer ssh.Signer
		if secret.KeyPassphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(keyBytes, []byte(secret.KeyPassphrase))
		} else {
			signer, err = ssh.ParsePrivateKey(keyBytes)
		}
		if err != nil {
			return nil, fmt.Errorf("解析 SSH 私钥失败: %w", err)
		}
		return ssh.PublicKeys(signer), nil
	default:
		return nil, fmt.Errorf("未知 SSH auth_type: %s", target.AuthType)
	}
}

func hostKeyCallback() (ssh.HostKeyCallback, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	knownHosts := filepath.Join(home, ".ssh", "known_hosts")
	if _, err := os.Stat(knownHosts); err != nil {
		return ssh.InsecureIgnoreHostKey(), nil
	}
	callback, err := knownhosts.New(knownHosts)
	if err != nil {
		return nil, fmt.Errorf("加载 known_hosts 失败: %w", err)
	}
	return callback, nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *ssh.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitStatus()
	}
	return -1
}

type limitedBuffer struct {
	buf       bytes.Buffer
	limit     int64
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		b.truncated = true
		return len(p), nil
	}
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.truncated = true
		return len(p), nil
	}
	if int64(len(p)) > remaining {
		b.truncated = true
		_, _ = b.buf.Write(p[:remaining])
		return len(p), nil
	}
	_, _ = b.buf.Write(p)
	return len(p), nil
}

func (b *limitedBuffer) String() string {
	return b.buf.String()
}

// shellQuote 使用模板包的 SSH 参数引用策略包装 sudo 的 sh -c 参数。
// 这里复用一次模板渲染，避免在 sudo 包装处引入第二套 shell escaping 规则。
func shellQuoteForSudo(value string) string {
	rendered, err := safetemplate.RenderShellTemplate("{{cmd}}", map[string]safetemplate.ParamRule{"cmd": {Type: safetemplate.ParamTypeString}}, map[string]string{"cmd": value})
	if err != nil {
		return "''"
	}
	return rendered
}
