package results

// 文件泄露落库（asset_fileleak）。
//
// 背景（2026-11-27）：服务端「资产管理 → 文件泄露」页面依赖节点写入 asset_fileleak，
// 而扫描端从来没有这个写入方 —— 和 NPoC 服务页面是同一类缺陷：读模型有、写侧缺失，页面恒空。
//
// 数据来源选 DirScan：它本来就在按字典撞路径，.env / *.bak / *.sql / .git/config 这些
// 泄露文件正是它的输出。这里只在「状态 2xx 且路径像泄露文件」时记一条，不把整个目录扫描结果倒进来。

import (
	"fmt"
	"net/url"
	"path"
	"strings"

	"go.mongodb.org/mongo-driver/bson"

	"github.com/Autumn-27/ScopeSentry-Scan/internal/mongodb"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/logger"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/utils"
)

const collFileLeak = "asset_fileleak"

type leakPattern struct {
	kind  string
	frags []string
}

// 高信号泄露路径：命中即认为是「本不该公开的文件」。
// 刻意只要高信号的：把 .conf/.ini/.log 也算进来，几乎每个站都会命中一堆噪音，
// 这个页面就又变成没人看的列表了。
var leakPatterns = []leakPattern{
	{"环境变量文件", []string{"/.env", "/.env.local", "/.env.prod", "/.env.production", "/.env.bak"}},
	{"版本库元数据", []string{"/.git/config", "/.git/head", "/.svn/entries", "/.hg/hgrc"}},
	{"数据库导出", []string{".sql", ".dump", ".sql.gz", ".mdb"}},
	{"备份/压缩包", []string{".zip", ".rar", ".7z", ".tar.gz", ".tgz", ".tar.bz2", ".bak", ".old", ".backup", ".swp"}},
	{"私钥/凭据", []string{"id_rsa", "id_dsa", "/.ssh/", "credentials.xml", "/etc/passwd", "/etc/shadow"}},
	{"配置残留", []string{"web.config.bak", "wp-config.php.bak", "config.php.bak", "config.inc.php.bak", ".ds_store", "composer.lock"}},
}

// ClassifyLeak 判断一个 DirScan 命中是不是文件泄露；返回可读的类型名。
func ClassifyLeak(rawURL string) (string, bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", false
	}
	p := strings.ToLower(u.Path)
	if p == "" || p == "/" {
		return "", false
	}
	base := path.Base(p)
	for _, lp := range leakPatterns {
		for _, frag := range lp.frags {
			if strings.Contains(p, frag) || strings.Contains(base, frag) {
				return lp.kind, true
			}
		}
	}
	return "", false
}

// FileLeak 记录一条已确认可访问的泄露文件。
// 同一 URL 只保留一行（重复扫描更新状态/长度/更新时间），避免每次扫都堆一条。
func (r *result) FileLeak(rawURL, site, kind string, status int, length int64) {
	if strings.TrimSpace(rawURL) == "" {
		return
	}
	if site == "" {
		if u, err := url.Parse(rawURL); err == nil {
			site = u.Host
		}
	}
	now := utils.Tools.GetTimeNow()
	_, err := mongodb.MongodbClient.Upsert(collFileLeak,
		bson.M{"url": rawURL},
		bson.M{
			"$set": bson.M{
				"url":            rawURL,
				"site":           site,
				"title":          kind,
				"status_code":    status,
				"content_length": length,
				"update_date":    now,
			},
			"$setOnInsert": bson.M{"insert_time": now},
		})
	if err != nil {
		logger.SlogWarnLocal(fmt.Sprintf("fileleak upsert %s error: %s", rawURL, err))
	}
}
