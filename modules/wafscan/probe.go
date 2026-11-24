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

var carriers = []carrier{
	{"query", func(p, target string) (string, string, string, map[string]string) {
		sep := "?"
		if strings.Contains(target, "?") {
			sep = "&"
		}
		u := target + sep + "wafscan=" + url.QueryEscape(p)
		return http.MethodGet, "", "", map[string]string{"__url": u}
	}},
	{"header-ua", func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodGet, "", "", map[string]string{"User-Agent": p}
	}},
	{"header-referer", func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodGet, "", "", map[string]string{"Referer": "https://wafscan.invalid/" + p}
	}},
	{"header-xff", func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodGet, "", "", map[string]string{"X-Forwarded-For": p}
	}},
	{"json", func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, `{"q":"` + p + `"}`, "application/json", nil
	}},
	{"json-gzip", func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, string(gz([]byte(`{"q":"` + p + `"}`))), "application/json",
			map[string]string{"Content-Encoding": "gzip"}
	}},
	{"json-utf16be", func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, string(utf16be(`{"q":"` + p + `"}`)), "application/json; charset=utf-16be", nil
	}},
	{"json-gzip-u16", func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, string(gz(utf16be(`{"q":"` + p + `"}`))), "application/json; charset=utf-16be",
			map[string]string{"Content-Encoding": "gzip"}
	}},
	{"form", func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, "q=" + url.QueryEscape(p), "application/x-www-form-urlencoded", nil
	}},
	{"form-gzip", func(p, _ string) (string, string, string, map[string]string) {
		return http.MethodPost, string(gz([]byte("q=" + url.QueryEscape(p)))), "application/x-www-form-urlencoded",
			map[string]string{"Content-Encoding": "gzip"}
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
	Carrier string `bson:"carrier" json:"carrier"`
	Class   string `bson:"class" json:"class"`
	State   string `bson:"state" json:"state"`
	Benign  int    `bson:"benign" json:"benign"`
	Payload int    `bson:"payload" json:"payload"`
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

func do(ctx context.Context, target, method, body, ctype string, headers map[string]string) (int, http.Header, error) {
	u := target
	if v, ok := headers["__url"]; ok {
		u = v
	}
	req, err := http.NewRequestWithContext(ctx, method, u, strings.NewReader(body))
	if err != nil {
		return 0, nil, err
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
		return 0, nil, err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, resp.Header, nil
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
	if code, h, err := do(ctx, base, http.MethodGet, "", "", nil); err == nil {
		_ = code
		prof.Vendor = fingerprint(h)
	}

	for _, c := range carriers {
		for _, f := range families {
			select {
			case <-ctx.Done():
				return prof, ctx.Err()
			default:
			}
			m1, b1, t1, h1 := c.Build(f.Benign, base)
			bcode, _, berr := do(ctx, base, m1, b1, t1, h1)
			time.Sleep(delay)
			m2, b2, t2, h2 := c.Build(f.Payload, base)
			pcode, _, perr := do(ctx, base, m2, b2, t2, h2)
			time.Sleep(delay)

			r := Result{Carrier: c.Name, Class: f.Name, Benign: bcode, Payload: pcode}
			switch {
			case berr != nil || perr != nil:
				r.State = StateInconclusive
			case blocked(bcode):
				r.State = StateInconclusive // 基线就被拦：无法归因
			case blocked(pcode):
				r.State = StateInspected
				prof.Inspected++
			case bcode < 400 && pcode < 400:
				r.State = StateNotInspected
				prof.Bypasses = append(prof.Bypasses, c.Name+":"+f.Name)
			default:
				r.State = StateAppRejected
			}
			if r.State == StateInconclusive {
				prof.Inconclusive++
			}
			prof.Results = append(prof.Results, r)
		}
	}

	// multipart 两个变体
	for _, asFile := range []bool{false, true} {
		name := "mp-field"
		if asFile {
			name = "mp-file"
		}
		for _, f := range families {
			bb, ct := buildMultipart(f.Benign, asFile)
			bcode, _, berr := do(ctx, base, http.MethodPost, bb, ct, nil)
			time.Sleep(delay)
			pb, ct2 := buildMultipart(f.Payload, asFile)
			pcode, _, perr := do(ctx, base, http.MethodPost, pb, ct2, nil)
			time.Sleep(delay)
			r := Result{Carrier: name, Class: f.Name, Benign: bcode, Payload: pcode}
			switch {
			case berr != nil || perr != nil, blocked(bcode):
				r.State = StateInconclusive
				prof.Inconclusive++
			case blocked(pcode):
				r.State = StateInspected
				prof.Inspected++
			case bcode < 400 && pcode < 400:
				r.State = StateNotInspected
				prof.Bypasses = append(prof.Bypasses, name+":"+f.Name)
			default:
				r.State = StateAppRejected
			}
			prof.Results = append(prof.Results, r)
		}
	}

	// 收口：一次「payload 被拦」都没观测到时，不能声称任何绕过。
	// 放行不等于绕过——只有「同载体 benign 放行 + payload 被拦」才建立得起基线。
	// 这是全项目一直在用的 catch-all 纪律（netguard.IsCatchAll 同理）。
	prof.WafActive = prof.Inspected > 0
	if !prof.WafActive {
		if len(prof.Bypasses) > 0 {
			prof.Note = "no blocking observed for any payload: host is catch-all or has no WAF rules; bypasses discarded"
		}
		prof.Bypasses = nil
	}
	return prof, nil
}
