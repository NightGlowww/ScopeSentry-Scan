package wafscan

import "testing"

// 跨编码守卫：压缩 benign 与明文 benign 不同形时，差分不可归因于 WAF。
// 这是从 waf-harness/wafprobe 移植的核心纪律——没有它，
// 「源站对压缩请求本来就返回别的东西」会被误判成「WAF 没检查」。
func TestFinalizeDivergenceGuard(t *testing.T) {
	p := &Profile{
		Inspected: 1, // 明文 XSS 被拦，说明这台确实有 WAF
		Bypasses:  []string{"json-gzip:xss"},
		Results: []Result{
			{Carrier: "json", Class: "xss", State: StateInspected, Benign: 404, Payload: 403, BenignLen: 0},
			// gzip benign 是 200/5000，与明文 benign 的 404/0 完全不同形
			{Carrier: "json-gzip", Class: "xss", State: StateNotInspected, Plain: "json", Benign: 200, Payload: 200, BenignLen: 5000, PayloadLen: 5002},
		},
	}
	finalize(p)
	if len(p.Bypasses) != 0 {
		t.Fatalf("不同形的压缩载体必须被剔除，仍有 %v", p.Bypasses)
	}
	if p.Diverged != 1 {
		t.Fatalf("应记 1 条 divergent，得到 %d", p.Diverged)
	}
	if p.Results[1].State != StateCarrierDivergent {
		t.Fatalf("状态应为 carrier_divergent，得到 %s", p.Results[1].State)
	}
}

func TestFinalizeKeepsSameShapeBypass(t *testing.T) {
	p := &Profile{
		Inspected: 1,
		Bypasses:  []string{"json-gzip:xss", "header-xff:xss"},
		Results: []Result{
			{Carrier: "json", Class: "xss", State: StateInspected, Benign: 404, Payload: 403, BenignLen: 0},
			{Carrier: "json-gzip", Class: "xss", State: StateNotInspected, Plain: "json", Benign: 404, Payload: 404, BenignLen: 0, PayloadLen: 0},
		},
	}
	finalize(p)
	if len(p.Bypasses) != 2 {
		t.Fatalf("同形时应保留绕过，得到 %v", p.Bypasses)
	}
	if p.GapType != "compression+header" {
		t.Fatalf("gapType 应为 compression+header，得到 %q", p.GapType)
	}
	if p.Evidence != "L2" {
		t.Fatalf("证据级别应为 L2，得到 %q", p.Evidence)
	}
}

func TestFinalizeOriginRejectsEncoding(t *testing.T) {
	p := &Profile{
		Results: []Result{
			{Carrier: "json", Class: "xss", State: StateInspected, Benign: 200, Payload: 403, BenignLen: 100},
			// 压缩 benign 直接 403、明文 benign 200 → 源站/边缘拒收该编码
			{Carrier: "json-gzip", Class: "xss", State: StateInconclusive, Plain: "json", Benign: 403, Payload: 403},
		},
	}
	finalize(p)
	if p.Results[1].State != StateOriginRejectsEncoding {
		t.Fatalf("应为 origin_rejects_encoding，得到 %s", p.Results[1].State)
	}
}

func TestSameShapeTolerance(t *testing.T) {
	if !sameShape(200, 1000, 200, 1150) {
		t.Fatalf("150 字节差在容差内，应判同形")
	}
	if sameShape(200, 1000, 200, 1500) {
		t.Fatalf("500 字节差超出容差，应判不同形")
	}
	if sameShape(200, 100, 403, 100) {
		t.Fatalf("状态码不同不是同形")
	}
}
