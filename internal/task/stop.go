package task

// 停止请求的兜底：取消 context 之后，如果任务在宽限期内还没有收尾，就退出进程让容器重启。
//
// 背景（2026-11-27）：`POST /api/task/stop` 返回 success，但节点 8 分钟后仍在跑同一个任务。
// 原因是取消 context 只能让「还没开始的目标」不再开始，正在跑的模块 goroutine
// （nuclei / SentryDir / katana 这些）并不会理会 ctx.Done —— 这是 Go 里杀不掉阻塞 goroutine 的老问题，
// watchdog.go 的注释里也记过一次同样的教训。
//
// 所以这里沿用本仓库既有的「退出进程让 Docker 重拉」手法：给停止请求一个宽限期，
// 到期还在跑就明确记录并 exit(1)。代价是一次冷启动（加载 POC/字典约 5-8 分钟），
// 收益是「停止」这个按钮不再骗人，节点不会为一个已取消的任务继续占着。

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/Autumn-27/ScopeSentry-Scan/pkg/logger"
)

// stopGrace 停止请求的宽限期：默认 90 秒，可用 STOP_GRACE_SEC 覆盖（0 = 不兜底）。
func stopGrace() time.Duration {
	if v := os.Getenv("STOP_GRACE_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return time.Duration(n) * time.Second
		}
	}
	return 90 * time.Second
}

// StartStopEscalation 在收到 stop_task 之后调用。
// 若宽限期内 activeTaskID 仍然是这个任务，说明模块没响应取消 → 退出进程。
func StartStopEscalation(id string) {
	grace := stopGrace()
	if grace == 0 {
		return
	}
	go func() {
		deadline := time.Now().Add(grace)
		for time.Now().Before(deadline) {
			cur, _ := activeTaskID.Load().(string)
			if cur != id {
				// 已经切走或正常收尾，不需要兜底
				return
			}
			time.Sleep(5 * time.Second)
		}
		cur, _ := activeTaskID.Load().(string)
		if cur != id {
			return
		}
		logger.SlogError(fmt.Sprintf(
			"stop escalation: 任务 %s 在 %s 内仍未停止（模块不响应取消），退出让容器重启", id, grace))
		time.Sleep(2 * time.Second) // 给日志落盘一点时间
		os.Exit(1)
	}()
}
