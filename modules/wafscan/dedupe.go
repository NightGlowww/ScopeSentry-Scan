package wafscan

import "net/url"

// probeKey 把 URL 归一成「scheme://host:port」，用于任务内去重。
//
// Probe 内部会把目标归一成 scheme://host/，所以同一主机不同路径会被重复探测；
// 2026-11-26 实测：ftp.id-watsonsbesti.com:8443 在一个任务里被扫了 6 次，每次 4 个 inconclusive。
func probeKey(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return u.Scheme + "://" + u.Host
}
