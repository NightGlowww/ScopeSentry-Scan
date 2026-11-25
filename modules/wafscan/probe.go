// Package wafscan 探测目标 WAF 及其「哪些载体不被检查」。
//
// 来源：waf-harness 在 9 个厂商、48 台生产主机上的实测结论（2026-11）。
// 核心事实：WAF 只检查它看得懂的编码形态 —— 压缩体（gzip）、非常规字符集（UTF-16BE）、
// 以及多数头部载体，普遍不被检查；multipart 文件部件在多个引擎上同样漏检。
//
// 本模块只做「测量」，不做攻击利用：每个载体先发 benign 建立基线，再发同一族的攻击串，
// 用三态判定（检查/未检查/不可测），避免把「应用拒绝」误判成「WAF 放过」。
package wafscan

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// 三态判定
const (
	StateInspected    = "inspected"     // benign 放行、payload 被拦 → 该载体被检查
	StateNotInspected = "not_inspected" // 两者都放行 → 该载体不被检查（可绕过）
	StateInconclusive = "inconclusive"  // benign 就被拦 → 不可测
	StateAppRejected  = "app_rejected"  // 两者同样状态且非 2xx → 应用拒绝，无法归因
	// 从成熟引擎（waf-harness/wafprobe）移植的两个状态：
	// carrier_divergent：同一载荷换个编码后，benign 自己的响应就变了 → 差分不可归因于 WAF
	// origin_rejects_encoding：源站拒收该编码（benign 就被打回），无法测
	StateCarrierDivergent      = "carrier_divergent"
	StateOriginRejectsEncoding = "origin_rejects_encoding"
)

// 攻击族：每族给 benign 与 payload 配对，避免单条串的误判。
type family struct {
	Name    string
	Benign  string
	Payload string
}

var families = []family{
	{"xss", "hello-wafscan", "<script>alert(1)</script>"},
	{"sqli", "1", "1 OR 1=1"},
	{"sqli-union", "1", "1 UNION SELECT NULL--"},
	{"lfi", "readme.txt", "../../../../etc/passwd"},
	{"log4j", "hello-wafscan", "${jndi:ldap://127.0.0.1:1389/a}"},
	{"ssti", "hello-wafscan", "{{7*7}}"},
}

// carrier 描述一个载体：如何把字符串放进请求。
type carrier struct {
	Name string
	// Plain 指向同族的「明文对照」载体名（如 json-gzip → json）。
	// 跨编码守卫用它：benign 在压缩与明文下若不同形，说明响应差异来自编码本身，
	// 不能算 WAF 放行（wafprobe 的 CARRIER_DIVERGENT）。
	Plain string
	// Build 返回 method / body / contentType / 额外头部。
	Build func(payload string, target string) (method, body, ctype string, headers map[string]string)
}

func gz(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func utf16be(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 0, len(u)*2)
	for _, r := range u {
		b = append(b, byte(r>>8), byte(r))
	}
	return b
}

// df 是 deflate（zlib 包装的 RFC1950）。有些 WAF 解 gzip 不解 deflate。
func df(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := zlib.NewWriterLevel(&buf, zlib.BestCompression)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

// carriers 是从 waf-harness/wafprobe 的 22 载体矩阵移植过来的子集：
//   - 覆盖 gzip / deflate / 嵌套压缩 / utf-16be / chunked / form / xml / text
//   - 覆盖 7 个常见请求头
//   - Plain 字段指向同族明文载体，供跨编码守卫判断「响应差异是否来自编码本身」
//
// brotli 需要第三方库，暂未纳入（记为已知缺口，见 docs/WAF-BYPASS.md）。
var carriers = []carrier{
	{Name: "query", Build: func(p, target string) (string, string, string, map[string]string) {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		u := target + sep + "wafscan=" + url.QueryEscape(p)
		return http.MethodGet, "", "", map[string]string{"__url": u}
	}},
	{Name: "header-ua", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodGet, "", "", map[string]string{"User-Agent": p}
	}},
	{Name: "header-referer", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodGet, "", "", map[string]string{"Referer": "https://wafscan.invalid/" + p}
	}},
	{Name: "header-xff", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodGet, "", "", map[string]string{"X-Forwarded-For": p}
	}},
	{Name: "header-cookie", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodGet, "", "", map[string]string{"Cookie": "wafscan=" + url.QueryEscape(p)}
	}},
	{Name: "header-xfh", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodGet, "", "", map[string]string{"X-Forwarded-Host": p + ".wafscan.invalid"}
	}},
	{Name: "header-origurl", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodGet, "", "", map[string]string{"X-Original-URL": "/" + url.QueryEscape(p)}
	}},
	{Name: "header-xfilename", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodGet, "", "", map[string]string{"X-File-Name": p}
	}},
	{Name: "json", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, `{"q":"` + p + `"}`, "application/json", nil
	}},
	{Name: "json-gzip", Plain: "json", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, string(gz([]byte(`{"q":"` + p + `"}`))), "application/json",
			map[string]string{"Content-Encoding": "gzip"}
	}},
	{Name: "json-deflate", Plain: "json", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, string(df([]byte(`{"q":"` + p + `"}`))), "application/json",
			map[string]string{"Content-Encoding": "deflate"}
	}},
	{Name: "json-gzip-deflate", Plain: "json", Build: func(p, _ string) (string, string, string, map[string]string) {
		// 先 deflate 再 gzip：WAF 只解一层时仍能拿到压缩内容。
		return http.MethodPost, string(gz(df([]byte(`{"q":"` + p + `"}`)))), "application/json",
			map[string]string{"Content-Encoding": "gzip"}
	}},
	{Name: "json-utf16be", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, string(utf16be(`{"q":"` + p + `"}`)), "application/json; charset=utf-16be", nil
	}},
	{Name: "json-gzip-u16", Plain: "json-utf16be", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, string(gz(utf16be(`{"q":"` + p + `"}`))), "application/json; charset=utf-16be",
			map[string]string{"Content-Encoding": "gzip"}
	}},
	{Name: "json-chunked", Plain: "json", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, string(gz([]byte(`{"q":"` + p + `"}`))), "application/json",
			map[string]string{"Content-Encoding": "gzip", "Transfer-Encoding": "chunked"}
	}},
	{Name: "form", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, "q=" + url.QueryEscape(p), "application/x-www-form-urlencoded", nil
	}},
	{Name: "form-gzip", Plain: "form", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, string(gz([]byte("q=" + url.QueryEscape(p)))), "application/x-www-form-urlencoded",
			map[string]string{"Content-Encoding": "gzip"}
	}},
	{Name: "xml", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, `<r><q>` + p + `</q></r>`, "text/xml", nil
	}},
	{Name: "xml-gzip", Plain: "xml", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, string(gz([]byte(`<r><q>` + p + `</q></r>`))), "text/xml",
			map[string]string{"Content-Encoding": "gzip"}
	}},
	{Name: "text-plain", Build: func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, p, "text/plain", nil
	}},
}

// multipart 载体单独构造（需要 boundary）。
func buildMultipart(p string, asFile bool) (string, string) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if asFile {
		part, _ := w.CreateFormFile("file", "wafscan.txt")
		_, _ = part.Write([]byte(p))
	} else {
		_ = w.WriteField("q", p)
	}
	_ = w.Close()
	return buf.String(), w.FormDataContentType()
}

// WAF 指纹：按响应头/Cookie 判厂商。
func fingerprint(h http.Header) string {
	l := func(k string) string { return strings.ToLower(h.Get(k)) }
	all := strings.ToLower(fmt.Sprint(h))
	switch {
	case h.Get("cf-ray") != "" || strings.Contains(l("Server"), "cloudflare"):
		return "cloudflare"
	case strings.Contains(all, "x-iinfo") || strings.Contains(all, "incap_ses") || strings.Contains(all, "visid_incap"):
		return "imperva"
	case strings.Contains(all, "akamai") || h.Get("X-Akamai-Transformed") != "" || strings.Contains(all, "ak_bmsc"):
		return "akamai"
	case h.Get("X-Amz-Cf-Id") != "" || h.Get("X-Amz-Cf-Pop") != "":
		return "cloudfront"
	case h.Get("X-Azure-Ref") != "" || h.Get("X-FD-HealthProbe") != "":
		return "azure-frontdoor"
	case strings.Contains(all, "bigipserver") || strings.Contains(all, "ts0") || strings.Contains(all, "f5avra"):
		return "f5"
	case strings.Contains(all, "x-sucuri-id"):
		return "sucuri"
	case strings.Contains(l("Server"), "gws") || strings.Contains(l("Server"), "google frontend"):
		return "google-frontend"
	case strings.Contains(all, "safeline") || strings.Contains(l("Server"), "tengine"):
		return "safeline"
	}
	return ""
}

// Result 单个载体×族的判定。
type Result struct {
	Carrier    string `bson:"carrier" json:"carrier"`
	Class      string `bson:"class" json:"class"`
	State      string `bson:"state" json:"state"`
	Benign     int    `bson:"benign" json:"benign"`
	Payload    int    `bson:"payload" json:"payload"`
	Plain      string `bson:"plain,omitempty" json:"plain,omitempty"`
	BenignLen  int    `bson:"benignLen" json:"benignLen"`
	PayloadLen int    `bson:"payloadLen" json:"payloadLen"`
}

// Profile 一个 host 的完整画像。
type Profile struct {
	Host         string   `bson:"host" json:"host"`
	URL          string   `bson:"url" json:"url"`
	Vendor       string   `bson:"vendor" json:"vendor"`
	Bypasses     []string `bson:"bypasses" json:"bypasses"`
	Inspected    int      `bson:"inspected" json:"inspected"`
	Inconclusive int      `bson:"inconclusive" json:"inconclusive"`
	Results      []Result `bson:"results" json:"results"`
	MeasuredAt   string   `bson:"measuredAt" json:"measuredAt"`
	// WafActive 表示「确实观测到拦截」。
	// inspected==0 说明这台主机对任何载荷都放行：要么没挂 WAF，要么是 catch-all
	// （SPA / 默认页 / 通配 200）。这时 bypasses 不能算数——实测
	// acceptance.cuponation.no 报过 bypasses=72 inspected=0，全是假绕过。
	WafActive bool   `bson:"wafActive" json:"wafActive"`
	Note      string `bson:"note,omitempty" json:"note,omitempty"`
	// 从成熟引擎移植：把「缺口长什么样」和「证据有多硬」也落库，
	// 否则下游只能看到一个 bypasses 数组，不知道自己面对的是压缩缺口还是 header 缺口。
	GapType  string `bson:"gapType,omitempty" json:"gapType,omitempty"`
	Evidence string `bson:"evidence,omitempty" json:"evidence,omitempty"`
	Diverged int    `bson:"diverged" json:"diverged"`
}

var (
	httpOnce sync.Once
	client   *http.Client
)

func httpClient() *http.Client {
	httpOnce.Do(func() {
		client = &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				MaxIdleConnsPerHost: 4,
				DisableKeepAlives:   false,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse // 跳转不跟随：307/302 也要能读状态码
			},
		}
	})
	return client
}

func do(ctx context.Context, target, method, body, ctype string, headers map[string]string) (int, int, http.Header, error) {
	u := target
	if v, ok := headers["__url"]; ok {
		u = v
	}
	req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(body))
	if err != nil {
		return 0, 0, nil, err
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for k, v := range headers {
		if k == "__url" {
			continue
		}
		req.Header.Set(k, v)
	}
	resp, err := httpClient().Do(req)
	if err != nil {
		return 0, 0, nil, err
	}
	defer resp.Body.Close()
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, int(n), resp.Header, nil
}

// blocked 判定：4xx 且不是 401/403 的「应用语义」也算拦；这里按 WAF 惯例取 403/406/501。
func blocked(code int) bool {
	return code == 403 || code == 406 || code == 501
}

// Probe 对单个 host 跑完整矩阵。
// 速率：每宿主串行 + 每条间隔 delay（默认 1s，符合「≤1 rps」纪律）。
func Probe(ctx context.Context, rawURL string, delay time.Duration) (*Profile, error) {
	if delay <= 0 {
		delay = time.Second
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid url: %s", rawURL)
	}
	base := u.Scheme + "://" + u.Host + "/"
	prof := &Profile{Host: u.Host, URL: base, MeasuredAt: time.Now().Format("2006-01-02 15:04:05")}

	// 先取一次基线的 WAF 指纹
	if code, _, h, err := do(ctx, base, http.MethodGet, "", "", nil); err == nil {
		_ = code
		prof.Vendor = fingerprint(h)
	}

	// 并发跑载体矩阵。
	//
	// 为什么必须并发：串行时 22 载体 × 6 族 × 2 请求，每请求还要等 delay，单主机 4–5 分钟；
	// 任务里几台主机直接顶到看门狗 30 分钟阈值——2026-11-26 实测连续两个任务因此被杀、
	// 节点反复冷启动。改成有界并发（WAFSCAN_CONC，默认 6）+ 全局限速：
	// 总速率仍由 delay 决定，单主机挂钟时间降到 1/N。
	type job struct {
		carrier, class, plain string
		benign, payload       string
		build                 func(string) (string, string, string, map[string]string)
	}
	var jobs []job
	for _, c := range carriers {
		cc := c
		for _, f := range families {
			ff := f
			jobs = append(jobs, job{carrier: cc.Name, class: ff.Name, plain: cc.Plain,
				benign: ff.Benign, payload: ff.Payload,
				build: func(p string) (string, string, string, map[string]string) { return cc.Build(p, base) }})
		}
	}
	for _, asFile := range []bool{false, true} {
		name := "mp-field"
		if asFile {
			name = "mp-file"
		}
		af := asFile
		for _, f := range families {
			ff := f
			jobs = append(jobs, job{carrier: name, class: ff.Name,
				benign: ff.Benign, payload: ff.Payload,
				build: func(p string) (string, string, string, map[string]string) {
					b, ct := buildMultipart(p, af)
					return http.MethodPost, b, ct, nil
				}})
		}
	}

	conc := envInt("WAFSCAN_CONC", 6)
	// 早停阈值：跑够这么多组合仍是「全 inconclusive / app_rejected」就收手。
	// 起因（2026-11-26 实测）：CloudFront 的 catch-all 主机上 132 个组合全是 inconclusive，
	// 264 次请求换回 0 信息，单主机白烧 4 分钟。
	earlyN := envInt("WAFSCAN_EARLY_N", 24)
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	var doneCount int
	aborted := false
	limiter := time.NewTicker(delay)
	defer limiter.Stop()
	ch := make(chan job)
	for i := 0; i < conc; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range ch {
				if runCtx.Err() != nil {
					return
				}
				<-limiter.C
				m1, b1, t1, h1 := j.build(j.benign)
				bcode, blen, _, berr := do(runCtx, base, m1, b1, t1, h1)
				<-limiter.C
				m2, b2, t2, h2 := j.build(j.payload)
				pcode, plen, _, perr := do(runCtx, base, m2, b2, t2, h2)

				r := Result{Carrier: j.carrier, Class: j.class, Benign: bcode, Payload: pcode,
					Plain: j.plain, BenignLen: blen, PayloadLen: plen}
				switch {
				case berr != nil || perr != nil, blocked(bcode):
					r.State = StateInconclusive
				case blocked(pcode):
					r.State = StateInspected
				case bcode < 400 && pcode < 400:
					r.State = StateNotInspected
				default:
					r.State = StateAppRejected
				}
				mu.Lock()
				switch r.State {
				case StateInconclusive:
					prof.Inconclusive++
				case StateInspected:
					prof.Inspected++
				case StateNotInspected:
					prof.Bypasses = append(prof.Bypasses, j.carrier+":"+j.class)
				}
				prof.Results = append(prof.Results, r)
				doneCount++
				if !aborted && doneCount >= earlyN && prof.Inspected == 0 && len(prof.Bypasses) == 0 {
					aborted = true
					cancel()
				}
				mu.Unlock()
			}
		}()
	}
	for _, j := range jobs {
		select {
		case <-ctx.Done():
			close(ch)
			wg.Wait()
			return prof, ctx.Err()
		case ch <- j:
		}
	}
	close(ch)
	wg.Wait()
	if aborted && prof.Note == "" {
		prof.Note = fmt.Sprintf("early-abort: first %d carriers showed no differentiation (all inconclusive/app_rejected); host treated as unmeasurable", earlyN)
	}

	// 收口：一次「payload 被拦」都没观测到时，不能声称任何绕过。
	// 放行不等于绕过——只有「同载体 benign 放行 + payload 被拦」才建立得起基线。
	// 这是全项目一直在用的 catch-all 纪律（netguard.IsCatchAll 同理）。
	// 先跑判定纪律：跨编码守卫会剔除「编码改变了 benign 自己」的假绕过，
	// 并把缺口类型/证据级别算出来。必须在 WafActive 收口之前，否则剔除后计数对不上。
	finalize(prof)

	prof.WafActive = prof.Inspected > 0
	if !prof.WafActive {
		if len(prof.Bypasses) > 0 {
			prof.Note = "no blocking observed for any payload: host is catch-all or has no WAF rules; bypasses discarded"
		}
		prof.Bypasses = nil
	}
	return prof, nil
}
