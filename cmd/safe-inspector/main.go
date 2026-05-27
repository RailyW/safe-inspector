// safe-inspector 是面向大语言模型的生产环境安全 CLI 工具层。
//
// 入口只负责把 os.Args/stdin/stdout/stderr 转交给 internal/cli；
// 具体配置、加密、模板、策略和执行逻辑均在 internal 包中实现。
package main

import (
	"os"

	"github.com/RailyW/safe-inspector/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
