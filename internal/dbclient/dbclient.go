// Package dbclient 封装 MySQL 一次性 SQL 执行。
//
// 本包只接收已经通过模板渲染和策略校验的 SQL；读查询返回 rows，
// 写查询返回 rows_affected。数据库密码只用于构造内存中的 DSN，不会输出。
package dbclient

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/RailyW/safe-inspector/internal/config"
	"github.com/RailyW/safe-inspector/internal/policy"
	"github.com/go-sql-driver/mysql"
)

// Result 是数据库执行结果，读查询使用 Rows，写查询使用 RowsAffected。
type Result struct {
	Columns      []string         `json:"columns,omitempty"`
	Rows         []map[string]any `json:"rows,omitempty"`
	RowsAffected int64            `json:"rows_affected,omitempty"`
	Truncated    bool             `json:"truncated"`
}

// Execute 使用 MySQL driver 执行一次 classic 模式下已经审批的 SQL 模板实例。
//
// 该入口仍会调用 policy.ValidateSQLExecution，确保 classic 模式下的读写分类、
// DDL/DCL 拒绝和多语句拒绝规则不会被绕过。
func Execute(ctx context.Context, target config.DBTarget, secret config.DBSecret, query string, args []any, kind string, timeout time.Duration, maxOutputBytes int64) (Result, error) {
	if err := policy.ValidateSQLExecution(query, kind); err != nil {
		return Result{}, err
	}
	return execute(ctx, target, secret, query, args, kind, timeout, maxOutputBytes)
}

// ExecuteApproved 执行已经由 LLM 或危险模式显式放行的 SQL。
//
// 该入口不再调用 classic SQL 风险校验，因为 LLM/danger 模式的语义就是可以越过
// deterministic policy。调用方仍必须传入 read/write kind，用于决定 Query 还是 Exec。
func ExecuteApproved(ctx context.Context, target config.DBTarget, secret config.DBSecret, query string, args []any, kind string, timeout time.Duration, maxOutputBytes int64) (Result, error) {
	return execute(ctx, target, secret, query, args, kind, timeout, maxOutputBytes)
}

func execute(ctx context.Context, target config.DBTarget, secret config.DBSecret, query string, args []any, kind string, timeout time.Duration, maxOutputBytes int64) (Result, error) {
	if target.Driver != "" && target.Driver != "mysql" {
		return Result{}, fmt.Errorf("当前仅支持 mysql driver，收到: %s", target.Driver)
	}
	if timeout <= 0 {
		timeout = time.Duration(config.DefaultTimeoutSeconds) * time.Second
	}
	if maxOutputBytes <= 0 {
		maxOutputBytes = config.DefaultMaxOutputBytes
	}
	if kind != policy.SQLKindRead && kind != policy.SQLKindWrite {
		return Result{}, fmt.Errorf("未知 SQL 执行类型 %q", kind)
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	db, err := sql.Open("mysql", buildDSN(target, secret, timeout))
	if err != nil {
		return Result{}, fmt.Errorf("打开 MySQL 连接失败: %w", err)
	}
	defer db.Close()

	if kind == policy.SQLKindWrite {
		execResult, err := db.ExecContext(ctx, query, args...)
		if err != nil {
			return Result{}, fmt.Errorf("执行写入 SQL 失败: %w", err)
		}
		affected, _ := execResult.RowsAffected()
		return Result{RowsAffected: affected}, nil
	}

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return Result{}, fmt.Errorf("执行查询 SQL 失败: %w", err)
	}
	defer rows.Close()
	return collectRows(rows, maxOutputBytes)
}

// buildDSN 根据非敏感目标配置和内存 secret 构造 MySQL DSN。
//
// DSN 只在内存中使用，不会被写入日志或 CLI 输出。
func buildDSN(target config.DBTarget, secret config.DBSecret, timeout time.Duration) string {
	cfg := mysql.NewConfig()
	cfg.User = target.Username
	cfg.Passwd = secret.Password
	cfg.Net = "tcp"
	cfg.Addr = fmt.Sprintf("%s:%d", target.Host, target.Port)
	cfg.DBName = target.Database
	cfg.ParseTime = true
	cfg.Timeout = timeout
	cfg.ReadTimeout = timeout
	cfg.WriteTimeout = timeout
	return cfg.FormatDSN()
}

// collectRows 读取查询结果并按 maxOutputBytes 做近似截断。
//
// 截断只影响返回给调用方的行数，不会取消已经完成的 SQL 查询。
func collectRows(rows *sql.Rows, maxOutputBytes int64) (Result, error) {
	columns, err := rows.Columns()
	if err != nil {
		return Result{}, fmt.Errorf("读取查询列失败: %w", err)
	}
	result := Result{Columns: columns, Rows: []map[string]any{}}
	var approxBytes int64

	for rows.Next() {
		raw := make([]any, len(columns))
		dest := make([]any, len(columns))
		for i := range raw {
			dest[i] = &raw[i]
		}
		if err := rows.Scan(dest...); err != nil {
			return Result{}, fmt.Errorf("扫描查询行失败: %w", err)
		}
		row := make(map[string]any, len(columns))
		for i, column := range columns {
			value := normalizeDBValue(raw[i])
			row[column] = value
			approxBytes += int64(len(column) + len(fmt.Sprint(value)))
		}
		if approxBytes > maxOutputBytes {
			result.Truncated = true
			break
		}
		result.Rows = append(result.Rows, row)
	}
	if err := rows.Err(); err != nil {
		return Result{}, fmt.Errorf("读取查询结果失败: %w", err)
	}
	return result, nil
}

// normalizeDBValue 把 database/sql 返回的底层值转换成适合 JSON 输出的值。
func normalizeDBValue(value any) any {
	switch v := value.(type) {
	case nil:
		return nil
	case []byte:
		return string(v)
	case time.Time:
		return v.Format(time.RFC3339Nano)
	default:
		return v
	}
}
