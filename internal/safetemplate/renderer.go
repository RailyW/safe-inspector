// Package safetemplate 实现 SSH 命令与 SQL 语句的安全模板渲染。
//
// 模板统一使用 {{name}} 命名参数。渲染前会先校验参数类型与约束；
// SSH 渲染会对参数进行 shell 单引号转义，SQL 渲染会把普通值转换为
// prepared statement 占位符，并只允许 identifier 参数直接进入 SQL 结构。
package safetemplate

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	ParamTypeEnum       = "enum"
	ParamTypeRegex      = "regex"
	ParamTypeInt        = "int"
	ParamTypeBool       = "bool"
	ParamTypeIdentifier = "identifier"
	ParamTypePath       = "path"
	ParamTypeString     = "string"
)

var placeholderPattern = regexp.MustCompile(`\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}`)
var identifierPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// ParamRule 描述单个模板参数的类型与约束。
// Enum 用于 enum 类型，Regex 用于 regex 类型；其他类型会使用内置校验规则。
type ParamRule struct {
	Type  string   `json:"type" yaml:"type"`
	Enum  []string `json:"enum,omitempty" yaml:"enum,omitempty"`
	Regex string   `json:"regex,omitempty" yaml:"regex,omitempty"`
}

// SQLRender 是 SQL 模板渲染结果。
// Query 中普通值已经替换成 ?，Args 保存 prepared statement 参数。
type SQLRender struct {
	Query string
	Args  []any
}

// RenderShellTemplate 校验并渲染 SSH 命令模板。
// 所有参数值都会进行 shell 单引号转义，避免参数内容突破模板边界。
func RenderShellTemplate(raw string, rules map[string]ParamRule, values map[string]string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", errors.New("命令模板不能为空")
	}
	rendered, err := replacePlaceholders(raw, rules, values, func(name string, rule ParamRule, value string) (string, error) {
		checked, err := validateValue(name, rule, value)
		if err != nil {
			return "", err
		}
		return shellQuote(checked), nil
	})
	if err != nil {
		return "", err
	}
	return rendered, nil
}

// RenderSQLTemplate 校验并渲染 SQL 模板。
// identifier 参数会以反引号安全引用；其他参数转为 ? 占位符并写入 Args。
func RenderSQLTemplate(raw string, rules map[string]ParamRule, values map[string]string) (SQLRender, error) {
	if strings.TrimSpace(raw) == "" {
		return SQLRender{}, errors.New("SQL 模板不能为空")
	}
	args := make([]any, 0)
	query, err := replacePlaceholders(raw, rules, values, func(name string, rule ParamRule, value string) (string, error) {
		checked, err := validateValue(name, rule, value)
		if err != nil {
			return "", err
		}
		if rule.Type == ParamTypeIdentifier {
			return "`" + checked + "`", nil
		}
		typedValue, err := typedSQLArg(rule, checked)
		if err != nil {
			return "", fmt.Errorf("参数 %q 类型转换失败: %w", name, err)
		}
		args = append(args, typedValue)
		return "?", nil
	})
	if err != nil {
		return SQLRender{}, err
	}
	return SQLRender{Query: query, Args: args}, nil
}

// ExtractPlaceholders 返回模板中出现过的参数名，主要用于错误提示和测试。
func ExtractPlaceholders(raw string) []string {
	matches := placeholderPattern.FindAllStringSubmatch(raw, -1)
	seen := make(map[string]bool, len(matches))
	names := make([]string, 0, len(matches))
	for _, match := range matches {
		name := match[1]
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	return names
}

func replacePlaceholders(raw string, rules map[string]ParamRule, values map[string]string, renderer func(string, ParamRule, string) (string, error)) (string, error) {
	var firstErr error
	out := placeholderPattern.ReplaceAllStringFunc(raw, func(token string) string {
		if firstErr != nil {
			return token
		}
		match := placeholderPattern.FindStringSubmatch(token)
		name := match[1]
		rule, ok := rules[name]
		if !ok {
			firstErr = fmt.Errorf("模板参数 %q 未声明约束", name)
			return token
		}
		value, ok := values[name]
		if !ok {
			firstErr = fmt.Errorf("缺少模板参数 %q", name)
			return token
		}
		rendered, err := renderer(name, rule, value)
		if err != nil {
			firstErr = err
			return token
		}
		return rendered
	})
	if firstErr != nil {
		return "", firstErr
	}
	for key := range values {
		if !containsPlaceholder(raw, key) {
			return "", fmt.Errorf("参数 %q 未被模板使用", key)
		}
	}
	return out, nil
}

func validateValue(name string, rule ParamRule, value string) (string, error) {
	if value == "" {
		return "", fmt.Errorf("参数 %q 不能为空", name)
	}
	switch rule.Type {
	case ParamTypeEnum:
		for _, candidate := range rule.Enum {
			if value == candidate {
				return value, nil
			}
		}
		return "", fmt.Errorf("参数 %q 不在允许枚举中", name)
	case ParamTypeRegex:
		if rule.Regex == "" {
			return "", fmt.Errorf("参数 %q 缺少 regex 约束", name)
		}
		matched, err := regexp.MatchString(rule.Regex, value)
		if err != nil {
			return "", fmt.Errorf("参数 %q regex 无效: %w", name, err)
		}
		if !matched {
			return "", fmt.Errorf("参数 %q 不匹配 regex 约束", name)
		}
		return value, nil
	case ParamTypeInt:
		if _, err := strconv.ParseInt(value, 10, 64); err != nil {
			return "", fmt.Errorf("参数 %q 不是整数", name)
		}
		return value, nil
	case ParamTypeBool:
		if _, err := strconv.ParseBool(value); err != nil {
			return "", fmt.Errorf("参数 %q 不是布尔值", name)
		}
		return value, nil
	case ParamTypeIdentifier:
		if !identifierPattern.MatchString(value) {
			return "", fmt.Errorf("参数 %q 不是安全标识符", name)
		}
		return value, nil
	case ParamTypePath:
		if strings.ContainsAny(value, "\x00\r\n") {
			return "", fmt.Errorf("参数 %q 包含非法路径字符", name)
		}
		return filepath.Clean(value), nil
	case ParamTypeString, "":
		if strings.ContainsAny(value, "\x00\r\n") {
			return "", fmt.Errorf("参数 %q 包含非法字符串字符", name)
		}
		return value, nil
	default:
		return "", fmt.Errorf("参数 %q 使用未知类型 %q", name, rule.Type)
	}
}

func typedSQLArg(rule ParamRule, value string) (any, error) {
	switch rule.Type {
	case ParamTypeInt:
		return strconv.ParseInt(value, 10, 64)
	case ParamTypeBool:
		return strconv.ParseBool(value)
	default:
		return value, nil
	}
}

func containsPlaceholder(raw string, name string) bool {
	for _, placeholder := range ExtractPlaceholders(raw) {
		if placeholder == name {
			return true
		}
	}
	return false
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'\''`) + "'"
}
