// fileleakprobe：在真实节点环境里验一次「文件泄露写库」这条链路。
//
// 为什么需要它：ClassifyLeak 有单元测试，但「命中后能不能真写进 asset_fileleak」
// 依赖容器里的 Mongo 配置。线上暂时没扫到 2xx 的泄露路径，用这个探针把写入路径打通验证，
// 避免又出现「页面恒空但没人知道是读还是坏」。
package main

import (
	"fmt"
	"os"
	"time"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/Autumn-27/ScopeSentry-Scan/internal/config"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/mongodb"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/results"
)

func main() {
	// 必须先加载配置：mongodb.Initialize 读的是 global.AppConfig 里的连接串，
	// 不先跑 config.Initialize() 会连到空地址直接 panic。
	config.Initialize()
	mongodb.Initialize()
	results.InitializeResults()

	probe := fmt.Sprintf("https://scopecheck.invalid/%d/.env", time.Now().Unix())
	kind, hit := results.ClassifyLeak(probe)
	if !hit {
		fmt.Println("CLASSIFY FAILED for", probe)
		os.Exit(2)
	}
	results.Results.FileLeak(probe, "scopecheck.invalid", kind, 200, 42)

	var got struct {
		URL    string `bson:"url"`
		Title  string `bson:"title"`
		Status int    `bson:"status_code"`
		Length int64  `bson:"content_length"`
	}
	if err := mongodb.MongodbClient.FindOne("asset_fileleak", bson.M{"url": probe}, nil, &got); err != nil {
		fmt.Println("READBACK FAILED:", err)
		os.Exit(3)
	}
	fmt.Printf("OK url=%s title=%s status=%d length=%d\n", got.URL, got.Title, got.Status, got.Length)
	// 清理交给调用方（mongosh），client 没有暴露删除方法
	fmt.Println("NOTE: 请手动清理该探针记录")
}
