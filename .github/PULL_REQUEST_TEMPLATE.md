## Summary / 概述

<!-- What does this PR do and why? / 这个 PR 做了什么，为什么？ -->

## Type of change / 变更类型

- [ ] Bug fix / 缺陷修复
- [ ] New feature / 新功能
- [ ] Refactor / 重构
- [ ] Documentation / 文档
- [ ] Chore / dependency update / 杂项 / 依赖更新

## Test plan / 测试计划

- [ ] `gofmt -s -w . && goimports -w -local github.com/flipcloud-ai/ezauth . && go vet ./...`
- [ ] `ginkgo -r --procs=4 --timeout=20m --race --trace --skip-package=github.com/flipcloud-ai/ezauth/test/e2e ./...`
- [ ] E2E tests (if applicable) / E2E 测试（如适用）: `ginkgo -r --procs=1 --timeout=20m --race --trace ./test/e2e/`

## Checklist / 检查清单

- [ ] Branch name follows `<type>/<issue>-<short-desc>` convention / 分支命名符合 `<type>/<issue>-<short-desc>` 规范
- [ ] Commits follow [Conventional Commits](https://www.conventionalcommits.org/) / Commit message 使用 Conventional Commits 格式
- [ ] No secrets or sensitive data included / 无 secrets 或敏感信息
- [ ] PR diff < 400 lines (if larger, explain in Summary) / PR diff < 400 行（如超过，请在概述中说明）
- [ ] New code coverage ≥ 80% / 新增代码覆盖率 ≥ 80%

Closes #
