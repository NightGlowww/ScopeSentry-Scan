// Package netguard 收口「这响应压根不算证据」的判定。
//
// 2026-11-24 对照 ARL-Next 后补：
//  1. 边缘网关的 418/421 空体拒收不是站点内容，落库只会制造假资产；
//  2. catch-all 站点对任意随机路径都回同一页，目录扫描在它上面只会产出噪音。
package netguard

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// IsGatewayRejection 判断是不是边缘网关的空体拒收（418/421）。
// 有正文的 418/421 放行——那是站点自己的响应。
func IsGatewayRejection(status int, contentLength int, body string) bool {
	if status != 418 && status != 421 {
		return false
	}
	if strings.TrimSpace(body) != "" {
		return false
	}
	return contentLength <= 0 || len(body) == 0
}

var (
	cacheMu sync.Mutex
	cache   = map[string]bool{}
)

// IsCatchAll 对同一个 host 只探测一次：取两条随机路径，若状态一致且正文完全相同，
// 判定为 catch-all（任意路径都回同一页）。取不到就返回 false，宁可不拦。
func IsCatchAll(rawURL string, timeout time.Duration) bool {
	if os.Getenv("DIRSCAN_CATCHALL") == "off" {
		return false
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	key := u.Scheme + "://" + u.Host
	cacheMu.Lock()
	if v, ok := cache[key]; ok {
		cacheMu.Unlock()
		return v
	}
	cacheMu.Unlock()

	if timeout <= 0 {
		timeout = 8 * time.Second
	}
	client := &http.Client{Timeout: timeout}
	status1, hash1, ok1 := probe(client, key+"/"+randomPath())
	status2, hash2, ok2 := probe(client, key+"/"+randomPath())
	catchAll := ok1 && ok2 && status1 == status2 && hash1 == hash2
	if catchAll && status1 != 200 && status1 != 403 && status1 != 404 && status1 != 418 && status1 != 421 {
		// 其他状态码下的“同页”更像是统一错误处理，不当 catch-all 处理，避免误杀。
		catchAll = false
	}
	cacheMu.Lock()
	cache[key] = catchAll
	cacheMu.Unlock()
	return catchAll
}

func probe(c *http.Client, target string) (int, string, bool) {
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		return 0, "", false
	}
	req.Header.Set("User-Agent", "ScopeSentry-catchall-probe")
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", false
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return resp.StatusCode, "", false
	}
	sum := sha256.Sum256(body)
	return resp.StatusCode, hex.EncodeToString(sum[:]), true
}

func randomPath() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return fmt.Sprintf("ss-%s.html", hex.EncodeToString(b))
}
