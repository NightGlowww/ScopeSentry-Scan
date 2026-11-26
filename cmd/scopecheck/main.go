// scopecheck：一次性的自检工具，用来回答「nuclei 到底有没有把响应体保存下来」。
//
// 背景：漏洞详情表一直是 0 字节的 request/response，所以 LLM 复核只能凭模板名猜。
// 怀疑点在于 ResponseSaveSize 没生效（nuclei 的 operators 在它为 0 时会把响应截成空串）。
// 这个工具用和线上完全相同的引擎构造参数，对一个本地 HTTP 服务跑一条内联模板，
// 直接打印 ResultEvent.Response 的长度——不依赖任何一次真实扫描命中。
//
// 用法：go run ./cmd/scopecheck   （或编译后直接在扫描节点上跑）
package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"time"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
)

const tpl = `id: ss-response-save-check

info:
  name: SS Response Save Check
  author: ss
  severity: info

http:
  - method: GET
    path:
      - "{{BaseURL}}/probe"
    matchers:
      - type: word
        words:
          - "SS_MARKER"
`

func main() {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><body>SS_MARKER hello-from-scopecheck</body></html>"))
	}))
	defer ts.Close()

	dir, err := os.MkdirTemp("", "scopecheck")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dir)
	tp := filepath.Join(dir, "check.yaml")
	if err := os.WriteFile(tp, []byte(tpl), 0o644); err != nil {
		panic(err)
	}

	// TPL / TARGET 给了就用真实模板 + 真实目标跑一次，用来对照「线上为什么没存响应」。
	tplPath := os.Getenv("TPL")
	target := ts.URL
	if tplPath != "" {
		target = os.Getenv("TARGET")
		if target == "" {
			fmt.Println("TPL 设了但 TARGET 为空")
			os.Exit(4)
		}
		fmt.Println("using real template:", tplPath, "target:", target)
	} else {
		tplPath = tp
	}


	// INSERT=1：走真实的 InsertVulnerabilityScan 写库路径，验证 Response 能否落进 vulnerabilityDetail。
	// 这条是「nuclei 保存了 16KB 响应，但详情表还是 0 字节」的最后一环，必须单独验。
	if os.Getenv("INSERT") == "1" {
		checkInsert(ts.URL)
		return
	}
	parser := templates.NewParser()
	ne, err := nuclei.NewThreadSafeNucleiEngineCtx(context.Background(), parser,
		nuclei.DisableUpdateCheck(), nuclei.WithResponseSaveSize(64*1024))
	if err != nil {
		fmt.Println("engine error:", err)
		os.Exit(2)
	}
	defer ne.Close()

	var got int
	var matched string
	ne.GlobalResultCallback(func(ev *output.ResultEvent) {
		if ev == nil {
			return
		}
		got = len(ev.Response)
		matched = ev.Matched
	})

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := ne.ExecuteNucleiWithOptsCtx(ctx, []string{target},
		nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{Templates: []string{tplPath}})); err != nil {
		fmt.Println("execute error:", err)
		os.Exit(3)
	}
	if got == 0 {
		fmt.Println("RESULT: response EMPTY (matched=" + matched + ") -> ResponseSaveSize 没生效")
		os.Exit(1)
	}
	fmt.Printf("RESULT: response saved, %d bytes (matched=%s)\n", got, matched)
}
