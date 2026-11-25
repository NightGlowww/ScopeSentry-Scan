package wafscan

import (
	"os"
	"strings"
	"sync"

	"github.com/Autumn-27/ScopeSentry-Scan/pkg/logger"
)

// wafscanAsync 默认 **异步**：wafscan 是补充信息，不该挡住后面的 DirScan / VulnerabilityScan。
//
// 起因（2026-11-26）：这里原本在模块退出时 wg.Wait()，而单主机探测要几十秒到几分钟；
// 一个任务几十台主机就卡在 wafscan 几小时，永远走不到漏洞扫描——
// 实测 vulnerability 集合只有 3 条，而任务跑了几十个。
//
// WAFSCAN_ASYNC=off 可以恢复「等探测完成再往下走」的旧行为。
func wafscanAsync() bool {
	return strings.ToLower(os.Getenv("WAFSCAN_ASYNC")) != "off"
}

func waitProbes(wg *sync.WaitGroup) {
	if wafscanAsync() {
		logger.SlogInfoLocal("wafscan: async mode, not waiting for probes")
		return
	}
	wg.Wait()
}
