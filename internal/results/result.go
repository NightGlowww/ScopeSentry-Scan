// results-------------------------------------
// @file      : result.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/9/17 21:12
// -------------------------------------------

package results

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/mongodb"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/types"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/logger"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"reflect"
)

type result struct {
}

var Results *result

func InitializeResults() {
	Results = &result{}
}

//func (r *result) Subdoamin(result *[]interface{}) bool {
//	_, err := mongodb.MongodbClient.InsertMany("subdomain", *result)
//	if err != nil {
//		logger.SlogError(fmt.Sprintf("SubdoaminResult error: %s", err))
//		return false
//	}
//	return true
//}

func (r *result) Insert(name string, result *[]interface{}) bool {
	_, err := mongodb.MongodbClient.InsertMany(name, *result)
	if err != nil {
		var writeException mongo.WriteException
		if errors.As(err, &writeException) {
			if name == "PageMonitoring" || name == "PageMonitoringBody" {
				for _, wErr := range writeException.WriteErrors {
					logger.SlogWarnLocal(fmt.Sprintf("插入失败的文档: %v, 错误: %v\n", wErr))
				}
			}
		}
		logger.SlogWarnLocal(fmt.Sprintf("insert %v error: %s", name, err))
		return false
	}
	return true
}

func (r *result) Update(result *[]interface{}, name string) bool {
	// 将 *[]interface{} 转换为 []types.BulkUpdateOperation
	var operations []mongo.WriteModel

	// 遍历传入的 result，逐一进行类型断言并构建 WriteModel
	for _, item := range *result {
		// 类型断言将 item 转换为 types.BulkUpdateOperation
		op, ok := item.(types.BulkUpdateOperation)
		if !ok {
			fmt.Println("Type assertion failed: item is not of type types.BulkUpdateOperation")
			return false
		}

		// 将 BulkUpdateOperation 转换为 mongo.UpdateOneModel 并添加到 operations 中
		updateModel := mongo.NewUpdateOneModel().
			SetFilter(op.Selector).
			SetUpdate(op.Update).
			SetUpsert(true) // 设置 Upsert 为 true，如果没有匹配文档，则插入新的文档

		operations = append(operations, updateModel)
	}
	// 调用 BulkWrite 批量写入或更新操作
	_, err := mongodb.MongodbClient.BulkWrite(name, operations)
	if err != nil {
		fmt.Println("Error during bulk write:", err)
		return false
	}
	return true
}

func (r *result) UpdateNow(op types.BulkUpdateOperation, name string) bool {
	// 将 *[]interface{} 转换为 []types.BulkUpdateOperation
	var operations []mongo.WriteModel

	// 将 BulkUpdateOperation 转换为 mongo.UpdateOneModel 并添加到 operations 中
	updateModel := mongo.NewUpdateOneModel().
		SetFilter(op.Selector).
		SetUpdate(op.Update).
		SetUpsert(true) // 设置 Upsert 为 true，如果没有匹配文档，则插入新的文档

	operations = append(operations, updateModel)
	// 调用 BulkWrite 批量写入或更新操作
	_, err := mongodb.MongodbClient.BulkWrite(name, operations)
	if err != nil {
		fmt.Println("Error during bulk write:", err)
		return false
	}
	return true
}

// InsertVulnerabilityScan 写入漏洞结果。
//
// 2026-11-24 改：hash 从「随机 16 位」改成「(模板ID + URL) 的 sha256 前 16 位」，
// 并按 hash 做 upsert。原来每次命中都生成新 hash，同一个洞扫两遍就变成两条记录
// （实测 LibreChat / Internal PKI 各重复一次）。
//
// 更新时用 $setOnInsert 保住 status：用户已经标成「已确认/已忽略」的记录，
// 重新扫描不能把状态重置回「未处理」。
func (r *result) InsertVulnerabilityScan(result *[]interface{}) {
	for _, v := range *result {
		var vulnResult *types.VulnResult
		if vr, ok := v.(*types.VulnResult); ok {
			vulnResult = vr
		}
		if vrPtr, ok := v.(**types.VulnResult); ok && vrPtr != nil {
			vulnResult = *vrPtr
		}
		if vulnResult == nil {
			fmt.Println("类型断言失败:", reflect.TypeOf(v))
			continue
		}

		sum := sha256.Sum256([]byte(vulnResult.VulnId + "|" + vulnResult.Url))
		vulnResult.Hash = hex.EncodeToString(sum[:])[:16]

		// 详情按 hash 覆盖写：同一洞再命中时更新证据，不新增行。
		//
		// 写失败不能静默：之前这里是赋值给下划线，详情表里 3 条记录全是 0 字节，
		// 看不出是「nuclei 没给响应」还是「写库失败」（2026-11-26）。
		// 现在两条都记：写库报错直接说原因；响应为空则连模板 id 一起记，
		// 用来区分「这个模板本来就没有响应」和「链路把响应丢了」。
		_, derr := mongodb.MongodbClient.Upsert("vulnerabilityDetail",
			bson.M{"hash": vulnResult.Hash},
			bson.M{"$set": types.VulnerabilityDetail{
				Hash:     vulnResult.Hash,
				Request:  vulnResult.Request,
				Response: vulnResult.Response,
			}})
		if derr != nil {
			logger.SlogWarnLocal(fmt.Sprintf("upsert vulnerabilityDetail %s error: %s (req=%dB resp=%dB)",
				vulnResult.Hash, derr, len(vulnResult.Request), len(vulnResult.Response)))
		} else if len(vulnResult.Response) == 0 {
			logger.SlogWarnLocal(fmt.Sprintf("vulnerability %s (%s) hit but empty response: req=%dB matched=%s",
				vulnResult.Hash, vulnResult.VulnId, len(vulnResult.Request), vulnResult.Matched))
		}

		vulnResult.Request = ""
		vulnResult.Response = ""

		// 观测字段（每次命中都可能变）与结论字段（第一次命中就定型）必须分开写。
		//
		// 2026-11-26 实测：同一条 pprof 漏洞被重扫后，
		//   · level 从人工判定后的 low 被模板 severity 顶回 high；
		//   · time 被刷成重扫当天，于是「2 天前的洞」每天都被算成 new24h。
		// 结论一旦下过就不该被机器覆盖 —— 这里把 level/time 挪进 $setOnInsert，
		// 另外补一个 lastSeenAt 记录最近一次命中，新鲜度照样看得见。
		observed := bson.M{
			"url": vulnResult.Url, "vulnid": vulnResult.VulnId, "vulname": vulnResult.VulName,
			"matched": vulnResult.Matched, "project": vulnResult.Project,
			"taskName": vulnResult.TaskName, "rootDomain": vulnResult.RootDomain,
			"tags": vulnResult.Tags, "lastSeenAt": vulnResult.Time,
		}
		firstSeen := bson.M{
			"status": vulnResult.Status,
			"level":  vulnResult.Level,
			"time":   vulnResult.Time,
		}
		_, err := mongodb.MongodbClient.Upsert("vulnerability",
			bson.M{"hash": vulnResult.Hash},
			bson.M{"$set": observed, "$setOnInsert": firstSeen})
		if err != nil {
			logger.SlogWarnLocal(fmt.Sprintf("upsert vulnerability %s error: %s", vulnResult.Hash, err))
		}
	}
}
