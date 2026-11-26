package progress

// 进程级「最后一次有进展」时间戳。
//
// 为什么单独一个包：任务看门狗在 internal/task，模块打点在 internal/handler，
// 两者不能互相 import（task 已经 import handler）。用一个无依赖的叶子包共享原子量，
// 谁都能写，谁都能读，不需要为此再引入回调。
//
// 2026-11-26 实测的问题：看门狗只在「一个目标跑完」时刷新打点，而单个目标的耗时
// 可以轻松超过 30 分钟（DirScan 23 分钟 + nuclei 5 分钟 + 其余模块）。于是健康的
// 扫描被判成停滞，节点 os.Exit(1) 自杀重启，重启后重新扫同一个目标又自杀——
// 日志里 09:41 和 21:43 两次都是这个原因，任务因此永远跑不完。
// 现在每个模块的开始/结束都会 Touch 一次，只有真正卡住（模块都不换）才会触发看门狗。

import (
	"sync/atomic"
	"time"
)

var lastUnix atomic.Int64

// Touch 记录一次进展。
func Touch() { lastUnix.Store(time.Now().Unix()) }

// Last 返回最后一次进展时间；零值表示进程启动后还没有任何进展。
func Last() time.Time {
	v := lastUnix.Load()
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(v, 0)
}
