package constants

// Version 网关版本号，单一真相源
// 参考 SOP-business-project-code-architecture.md §7.4
// 使用 var 而非 const，预留 CI/CD 通过 ldflags 注入版本号的能力
var Version = "1.4.0"
