package cli

import (
	"fmt"
	"strings"

	"github.com/RailyW/safe-inspector/internal/safetemplate"
)

type multiFlag []string

func (m *multiFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiFlag) Set(value string) error {
	*m = append(*m, value)
	return nil
}

func parseKeyValueParams(values []string) (map[string]string, error) {
	params := make(map[string]string, len(values))
	for _, item := range values {
		key, value, ok := strings.Cut(item, "=")
		if !ok || key == "" {
			return nil, fmt.Errorf("参数 %q 必须使用 key=value 格式", item)
		}
		params[key] = value
	}
	return params, nil
}

func parseParamRules(values []string) (map[string]safetemplate.ParamRule, error) {
	rules := make(map[string]safetemplate.ParamRule, len(values))
	for _, item := range values {
		name, spec, ok := strings.Cut(item, ":")
		if !ok || name == "" || spec == "" {
			return nil, fmt.Errorf("模板参数 %q 必须使用 name:type 或 name:type=value 格式", item)
		}
		rule, err := parseParamRule(spec)
		if err != nil {
			return nil, fmt.Errorf("模板参数 %q 无效: %w", name, err)
		}
		rules[name] = rule
	}
	return rules, nil
}

func parseParamRule(spec string) (safetemplate.ParamRule, error) {
	if strings.HasPrefix(spec, "enum=") {
		items := strings.Split(strings.TrimPrefix(spec, "enum="), ",")
		if len(items) == 0 || items[0] == "" {
			return safetemplate.ParamRule{}, fmt.Errorf("enum 至少需要一个值")
		}
		return safetemplate.ParamRule{Type: safetemplate.ParamTypeEnum, Enum: items}, nil
	}
	if strings.HasPrefix(spec, "regex=") {
		pattern := strings.TrimPrefix(spec, "regex=")
		if pattern == "" {
			return safetemplate.ParamRule{}, fmt.Errorf("regex 不能为空")
		}
		return safetemplate.ParamRule{Type: safetemplate.ParamTypeRegex, Regex: pattern}, nil
	}
	switch spec {
	case safetemplate.ParamTypeInt,
		safetemplate.ParamTypeBool,
		safetemplate.ParamTypeIdentifier,
		safetemplate.ParamTypePath,
		safetemplate.ParamTypeString:
		return safetemplate.ParamRule{Type: spec}, nil
	default:
		return safetemplate.ParamRule{}, fmt.Errorf("未知参数类型 %q", spec)
	}
}
