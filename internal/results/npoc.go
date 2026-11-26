package results

// NPoC 服务落库（asset_npoc_service）。
//
// 背景（2026-11-27）：服务端「资产管理 → NPoC 服务」页面依赖节点写入 asset_npoc_service，
// 而扫描端从来没有这个写入方 —— 页面因此恒为空，界面上一直挂着「该写入方尚未实现」。
//
// 这里不新造一套识别逻辑，而是复用 fingerprintx：它本身就是「发协议握手、收到正确响应才算数」，
// 也就是 NPoC 要的那个「证明」。只有拿到协议匹配才写，不靠端口号猜服务。
//
// 字段与 ARL-Next 对齐（服务端 models.NpocServiceRow）：scheme / host / port / target / insert_time。

import (
	"fmt"
	"strings"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/Autumn-27/ScopeSentry-Scan/internal/mongodb"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/logger"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/utils"
)

const collNpoc = "asset_npoc_service"

// Npoc 记录一条「已证实」的服务。protocol 来自 fingerprintx 的协议匹配结果。
// 同一 host:port 只保留一行（重复命中更新 insert_time），避免每次扫描都堆重复。
func (r *result) Npoc(host, port, protocol string) {
	host = strings.TrimSpace(host)
	port = strings.TrimSpace(port)
	protocol = strings.TrimSpace(protocol)
	if host == "" || port == "" || protocol == "" {
		return
	}
	scheme := strings.ToLower(protocol)
	target := host + ":" + port
	_, err := mongodb.MongodbClient.Upsert(collNpoc,
		bson.M{"host": host, "port": port},
		bson.M{"$set": bson.M{
			"scheme":      scheme,
			"host":        host,
			"port":        port,
			"target":      target,
			"insert_time": utils.Tools.GetTimeNow(),
		}})
	if err != nil {
		// 写失败要说出来：这个页面以前就是因为「写入方不存在」而恒空，
		// 再静默吞一次错误等于把同一个坑挖第二遍。
		logger.SlogWarnLocal(fmt.Sprintf("npoc upsert %s (%s) error: %s", target, scheme, err))
	}
}
