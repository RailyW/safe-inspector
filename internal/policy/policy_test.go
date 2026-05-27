package policy

import "testing"

func TestValidateSQLExecutionAllowsReadQueries(t *testing.T) {
	for _, query := range []string{
		"select * from users where id = ?",
		"SHOW PROCESSLIST",
		"describe users",
		"EXPLAIN select * from users",
	} {
		if err := ValidateSQLExecution(query, SQLKindRead); err != nil {
			t.Fatalf("read query %q was rejected: %v", query, err)
		}
	}
}

func TestValidateSQLExecutionRequiresWriteKindForDML(t *testing.T) {
	if err := ValidateSQLExecution("update users set name = ? where id = ?", SQLKindRead); err == nil {
		t.Fatalf("write query was accepted as read template")
	}
	if err := ValidateSQLExecution("update users set name = ? where id = ?", SQLKindWrite); err != nil {
		t.Fatalf("approved write template was rejected: %v", err)
	}
}

func TestValidateSQLExecutionRejectsDDLAndMultiStatement(t *testing.T) {
	for _, query := range []string{
		"drop table users",
		"alter table users add column nickname varchar(32)",
		"select * from users; select * from orders",
	} {
		if err := ValidateSQLExecution(query, SQLKindWrite); err == nil {
			t.Fatalf("dangerous query %q was accepted", query)
		}
	}
}

func TestValidateSudoPolicyRequiresTargetPermission(t *testing.T) {
	if err := ValidateSudoPolicy(false, true); err == nil {
		t.Fatalf("sudo template was accepted on target without sudo permission")
	}
	if err := ValidateSudoPolicy(true, true); err != nil {
		t.Fatalf("sudo template was rejected on target with sudo permission: %v", err)
	}
	if err := ValidateSudoPolicy(false, false); err != nil {
		t.Fatalf("non-sudo template should not require sudo permission: %v", err)
	}
}
