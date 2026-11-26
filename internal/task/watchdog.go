package task

import (
	"fmt"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/Autumn-27/ScopeSentry-Scan/internal/progress"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/logger"
)

// 任务停滞看门狗。
//
// 为什么需要它：2026-11-25 实测，一个 superdrug 任务在 URLScan 之后**15 分钟没有任何输出**，
// CPU 1.5%，而队列里还有 34 个任务排队。手动发 stop_task 之后日志显示 "stop task success"，
// 但任务主 goroutine 仍卡在 wg.Wait()——上下文取消了，阻塞中的目标 goroutine 不理会取消，
// 于是这个唯一节点就一直耗在那里。之前那两个 superdrug 任务这样耗了 23 小时。
//
// 做法：记录「最后一次有进展的时间」（任务开始、每个目标完成时更新），
// 每分钟检查一次；超过 STALL_TIMEOUT_MIN（默认 30 分钟）就主动退出进程，
// 由容器的 restart 策略拉起来重新取任务。
//
// 为什么是退出进程而不是取消上下文：Go 杀不掉卡住的 goroutine，
// 取消上下文已经在本次事件里被证明无效。重启整进程是唯一能真正释放节点的手段，
// 代价是冷启动（加载 POC/字典约 15 分钟），但比空转几小时好。
var (
	activeTaskID atomic.Value // string；空串表示没有任务在跑
)

func init() {
	activeTaskID.Store("")
}

// markTaskActive 任务开始时调用。
func markTaskActive(id string) {
	activeTaskID.Store(id)
	markProgress()
}

// markTaskIdle 任务正常结束时调用。
func markTaskIdle() {
	activeTaskID.Store("")
}

// markProgress 刷新进展打点。
// 注意：handler 里每个模块的开始/结束也会 Touch 同一个时间戳（见 internal/progress），
// 所以「一个目标跑很久」不再等于「停滞」。
func markProgress() {
	progress.Touch()
}

// stallTimeout 从环境变量读，默认 30 分钟。
func stallTimeout() time.Duration {
	if v := os.Getenv("STALL_TIMEOUT_MIN"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return time.Duration(n) * time.Minute
		}
	}
	return 30 * time.Minute
}

// StartStallWatchdog 在进程启动时调用一次。STALL_WATCHDOG=off 关闭。
func StartStallWatchdog() {
	if os.Getenv("STALL_WATCHDOG") == "off" {
		logger.SlogInfoLocal("stall watchdog disabled")
		return
	}
	limit := stallTimeout()
	logger.SlogInfoLocal(fmt.Sprintf("stall watchdog started (limit=%s)", limit))
	go func() {
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for range t.C {
			id, _ := activeTaskID.Load().(string)
			if id == "" {
				continue
			}
			last := progress.Last()
			if last.IsZero() {
				continue
			}
			idle := time.Since(last)
			if idle < limit {
				continue
			}
			logger.SlogError(fmt.Sprintf("stall watchdog: task %s has no progress for %s (limit %s), exiting to let container restart", id, idle.Round(time.Second), limit))
			// 给日志落盘一点时间
			time.Sleep(2 * time.Second)
			os.Exit(1)
		}
	}()
}
