package safetemplate

import "testing"

func TestRenderShellTemplateValidatesAndQuotesParameters(t *testing.T) {
	rendered, err := RenderShellTemplate(
		"systemctl status {{service}}",
		map[string]ParamRule{
			"service": {Type: ParamTypeEnum, Enum: []string{"nginx", "mysql"}},
		},
		map[string]string{"service": "nginx"},
	)
	if err != nil {
		t.Fatalf("RenderShellTemplate returned error: %v", err)
	}
	if rendered != "systemctl status 'nginx'" {
		t.Fatalf("rendered command mismatch: %q", rendered)
	}
}

func TestRenderShellTemplateRejectsMissingAndInvalidParameters(t *testing.T) {
	rules := map[string]ParamRule{
		"service": {Type: ParamTypeEnum, Enum: []string{"nginx"}},
	}

	if _, err := RenderShellTemplate("systemctl status {{service}}", rules, map[string]string{}); err == nil {
		t.Fatalf("missing parameter was accepted")
	}
	if _, err := RenderShellTemplate("systemctl status {{service}}", rules, map[string]string{"service": "ssh"}); err == nil {
		t.Fatalf("enum mismatch was accepted")
	}
}

func TestRenderSQLTemplateUsesPlaceholdersAndQuotesIdentifiers(t *testing.T) {
	rendered, err := RenderSQLTemplate(
		"select * from {{table}} where id = {{id}}",
		map[string]ParamRule{
			"table": {Type: ParamTypeIdentifier},
			"id":    {Type: ParamTypeInt},
		},
		map[string]string{"table": "orders", "id": "42"},
	)
	if err != nil {
		t.Fatalf("RenderSQLTemplate returned error: %v", err)
	}
	if rendered.Query != "select * from `orders` where id = ?" {
		t.Fatalf("rendered SQL mismatch: %q", rendered.Query)
	}
	if len(rendered.Args) != 1 || rendered.Args[0] != int64(42) {
		t.Fatalf("rendered SQL args mismatch: %#v", rendered.Args)
	}
}

func TestRenderSQLTemplateRejectsUnsafeIdentifier(t *testing.T) {
	_, err := RenderSQLTemplate(
		"select * from {{table}}",
		map[string]ParamRule{"table": {Type: ParamTypeIdentifier}},
		map[string]string{"table": "orders;drop table users"},
	)
	if err == nil {
		t.Fatalf("unsafe SQL identifier was accepted")
	}
}
