package wafscan

import (
	"strings"
)

// finalize 在一轮载体扫描结束后做三件事（全部移植自 waf-harness/wafprobe 的判定纪律）：
//
//  1. 跨编码守卫：压缩载体的 benign 若与同族明文 benign 不同形，说明响应差异来自编码本身，
//     不能算「WAF 没检查」，标 carrier_divergent 并从 bypasses 里剔除。
//  2. 源站拒收编码：benign 压缩就被 403/406/501、而明文 benign 正常 → 是源站/边缘直接拒收该编码，
//     不是可绕过的缺口，标 origin_rejects_encoding。
//  3. 归纳缺口类型与证据级别，写进 Profile，供下游（intel / 报告）直接用。
func finalize(p *Profile) {
	if p == nil || len(p.Results) == 0 {
		return
	}
	// 明文参照：carrier|class -> benign 状态与长度
	type shape struct{ code, length int }
	plain := map[string]shape{}
	for _, r := range p.Results {
		if r.Plain == "" {
			plain[r.Carrier+"|"+r.Class] = shape{r.Benign, r.BenignLen}
		}
	}

	kept := p.Bypasses[:0]
	diverged := 0
	for _, tag := range p.Bypasses {
		name, class := splitTag(tag)
		ref, has := plainLookup(p, name)
		if !has {
			kept = append(kept, tag)
			continue
		}
		var self *Result
		for i := range p.Results {
			if p.Results[i].Carrier == name && p.Results[i].Class == class {
				self = &p.Results[i]
				break
			}
		}
		if self == nil {
			continue
		}
		refShape := plain[ref+"|"+class]
		if !sameShape(self.Benign, self.BenignLen, refShape.code, refShape.length) {
			// 编码把 benign 自己就改变了 → 差分不可归因
			self.State = StateCarrierDivergent
			diverged++
			continue
		}
		kept = append(kept, tag)
	}
	p.Bypasses = kept
	p.Diverged = diverged

	// 源站拒收编码：压缩 benign 被拦、明文 benign 正常
	for i := range p.Results {
		r := &p.Results[i]
		if r.Plain == "" || r.State != StateInconclusive {
			continue
		}
		refShape := plain[r.Plain+"|"+r.Class]
		if blocked(r.Benign) && refShape.code > 0 && !blocked(refShape.code) {
			r.State = StateOriginRejectsEncoding
		}
	}

	// 归纳缺口类型
	has := func(prefix string) bool {
		for _, tag := range p.Bypasses {
			if strings.HasPrefix(tag, prefix) {
				return true
			}
		}
		return false
	}
	parts := []string{}
	if has("json-gzip") || has("json-deflate") || has("form-gzip") || has("xml-gzip") || has("json-gzip-") {
		parts = append(parts, "compression")
	}
	if has("header-") {
		parts = append(parts, "header")
	}
	if has("query") {
		parts = append(parts, "query")
	}
	if has("form:") || has("xml:") || has("text-plain:") {
		parts = append(parts, "partial-body")
	}
	p.GapType = strings.Join(parts, "+")

	// 证据级别：只有在「明文载体被检查、压缩同族未被检查」时才够 L2。
	if p.GapType != "" && p.Inspected > 0 {
		p.Evidence = "L2"
	}
}

func splitTag(tag string) (string, string) {
	if i := strings.LastIndex(tag, ":"); i > 0 {
		return tag[:i], tag[i+1:]
	}
	return tag, ""
}

// plainLookup 找到某压缩载体对应的明文载体名。
func plainLookup(p *Profile, name string) (string, bool) {
	for _, c := range carriers {
		if c.Name == name && c.Plain != "" {
			return c.Plain, true
		}
	}
	return "", false
}

// sameShape 用「状态码相同 + 长度在容差内」判断两次响应是否同形。
// 容差 max(200B, 2%)：实测 benign 响应逐字节稳定，留余量是为了吸收应用回显载荷。
func sameShape(c1, l1, c2, l2 int) bool {
	if c1 != c2 {
		return false
	}
	d := l1 - l2
	if d < 0 {
		d = -d
	}
	tol := l1 / 50
	if tol < 200 {
		tol = 200
	}
	return d <= tol
}
