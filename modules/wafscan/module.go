package wafscan

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Autumn-27/ScopeSentry-Scan/internal/contextmanager"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/interfaces"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/mongodb"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/options"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/types"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/logger"
	"go.mongodb.org/mongo-driver/bson"
)

// Runner 在目录扫描之后、漏洞扫描之前，对每个 HTTP 资产做一次 WAF 载体画像。
//
// 为什么放在这里：漏洞扫描（nuclei）的载荷大多走 query/body，一旦被 WAF 拦就是零结果。
// 先测出「这台主机哪个载体不被检查」，后续人工/自动化就能直接换载体打，而不是盲试。
type Runner struct {
	Option     *options.TaskOptions
	NextModule interfaces.ModuleRunner
	Input      chan interface{}
}

func NewRunner(op *options.TaskOptions, nextModule interfaces.ModuleRunner) *Runner {
	return &Runner{Option: op, NextModule: nextModule}
}

// 单节点同时最多 2 台主机在探测：每台约 60 次请求、1 rps，串行会把任务拖太久。
var probeSem = make(chan struct{}, 2)

// 同一 host 只测一次（一个任务里同主机的 URL 可能几十条）。
var measured sync.Map

func (r *Runner) ModuleRun() error {
	var wg sync.WaitGroup
	for {
		select {
		case <-contextmanager.GlobalContextManagers.GetContext(r.Option.ID).Done():
			wg.Wait()
			r.NextModule.CloseInput()
			return nil
		case data, ok := <-r.Input:
			if !ok {
				r.NextModule.CloseInput()
				wg.Wait()
				logger.SlogInfoLocal(fmt.Sprintf("module %v target %v close resultChan", r.GetName(), r.Option.Target))
				return nil
			}
			// 数据继续往下游走，探测不阻塞主链
			r.NextModule.GetInput() <- data

			u := extractURL(data)
			if u == "" || !wafscanEnabled() {
				continue
			}
			// 去重键用「scheme://host:port」而不是完整 URL：
			// Probe 内部会把目标归一成 scheme://host/，所以同主机不同路径会重复探测。
			// 2026-11-26 实测：ftp.id-watsonsbesti.com:8443 在同一任务里被扫了 6 次，
			// 每次 4 个 inconclusive，全是白烧的请求。
			if _, loaded := measured.LoadOrStore(probeKey(u), true); loaded {
				continue
			}
			wg.Add(1)
			go func(target string, id string) {
				defer wg.Done()
				probeSem <- struct{}{}
				defer func() { <-probeSem }()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
				defer cancel()
				// delay 从 1s 降到 150ms：全局限速是硬瓶颈（并发不放大速率），
				// 132 组合 × 2 请求 × 1s = 4.4 分钟/主机，降到 150ms 后约 40 秒。
				d := time.Duration(envInt("WAFSCAN_DELAY_MS", 150)) * time.Millisecond
				prof, err := Probe(ctx, target, d)
				if err != nil {
					logger.SlogWarnLocal(fmt.Sprintf("wafscan %s: %v", target, err))
					return
				}
				prof.Host = hostOf(target)
				if err := saveProfile(prof, id); err != nil {
					logger.SlogWarnLocal(fmt.Sprintf("wafscan save %s: %v", target, err))
					return
				}
				logger.SlogInfoLocal(fmt.Sprintf("wafscan %s vendor=%q wafActive=%v bypasses=%d inspected=%d inconclusive=%d",
					prof.Host, prof.Vendor, prof.WafActive, len(prof.Bypasses), prof.Inspected, prof.Inconclusive))
			}(u, r.Option.ID)
		}
	}
}

// wafscanEnabled 允许用环境变量关掉（大任务里想省请求时）：WAFSCAN=off。
func wafscanEnabled() bool {
	return strings.ToLower(os.Getenv("WAFSCAN")) != "off"
}

func extractURL(data interface{}) string {
	switch v := data.(type) {
	case types.AssetHttp:
		return v.URL
	case *types.AssetHttp:
		if v != nil {
			return v.URL
		}
	case types.UrlResult:
		return v.Output
	case *types.UrlResult:
		if v != nil {
			return v.Output
		}
	}
	return ""
}

func hostOf(raw string) string {
	if i := len("https://"); len(raw) > i && raw[:i] == "https://" {
		raw = raw[i:]
	} else if len(raw) > 7 && raw[:7] == "http://" {
		raw = raw[7:]
	}
	for i, c := range raw {
		if c == '/' || c == '?' || c == '#' {
			return raw[:i]
		}
	}
	return raw
}

// bestCarrier 从 "carrier:class" 列表里挑出现最多的载体名。
func bestCarrier(list []string) string {
	count := map[string]int{}
	for _, s := range list {
		name := s
		if i := strings.Index(s, ":"); i > 0 {
			name = s[:i]
		}
		count[name]++
	}
	best, n := "", 0
	for k, v := range count {
		if v > n || (v == n && k < best) {
			best, n = k, v
		}
	}
	return best
}

func saveProfile(p *Profile, taskID string) error {
	if mongodb.MongodbClient == nil {
		return fmt.Errorf("mongodb not ready")
	}
	doc := bson.M{
		"host": p.Host, "url": p.URL, "vendor": p.Vendor,
		"bypasses": p.Bypasses, "inspected": p.Inspected, "inconclusive": p.Inconclusive,
		"results": p.Results, "measuredAt": p.MeasuredAt, "taskName": taskID,
		// recommendedCarrier：命中次数最多的载体，给「用哪条载体重放」当默认值。
		"recommendedCarrier": bestCarrier(p.Bypasses),
		// wafActive=false 的画像（一次拦截都没观测到）不参与漏洞回填，
		// 否则 catch-all 主机上的「全载体可绕过」会被当成真的绕过写进报告。
		"wafActive": p.WafActive, "note": p.Note,
	}
	_, err := mongodb.MongodbClient.Upsert("waf_profile", bson.M{"host": p.Host}, bson.M{"$set": doc})
	return err
}

func (r *Runner) SetInput(ch chan interface{}) { r.Input = ch }
func (r *Runner) GetInput() chan interface{}   { return r.Input }
func (r *Runner) CloseInput() {
	if r.Input != nil {
		close(r.Input)
	}
}
func (r *Runner) GetName() string { return "WafScan" }
