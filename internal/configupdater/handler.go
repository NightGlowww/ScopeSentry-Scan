// configupdater-------------------------------------
// @file      : handler.go
// @author    : Autumn
// @contact   : rainy-autumn@outlook.com
// @time      : 2024/11/2 15:11
// -------------------------------------------

package configupdater

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/global"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/handler"
	"github.com/Autumn-27/ScopeSentry-Scan/internal/redis"
	"github.com/Autumn-27/ScopeSentry-Scan/pkg/logger"
	"os"
	"strconv"
	"strings"
	"time"
)

type Message struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Content string `json:"content"`
}

func handleRefreshConfigMessage(jsonData Message) {
	switch jsonData.Type {
	case "system":
		UpdateSystemConfig(jsonData.Content)
	case "dictionary":
		Updatedictionary(jsonData.Content)
	case "subfinder":
		UpdateSubfinderApiConfig()
	case "rad":
		UpdateRadConfig()
	case "sensitive":
		UpdateSensitive()
	case "nodeConfig":
		UpdateNode(jsonData.Content)
	case "project":
		UpdateProject()
	case "notification":
		UpdateNotification()
	case "stop_task":
		handler.TaskHandle.StopTask(jsonData.Content)
	case "delete_task":
		handler.TaskHandle.DeleteTask(jsonData.Content)
	case "install_plugin":
		InstallPlugin(jsonData.Content)
	case "delete_plugin":
		DeletePlugin(jsonData.Content)
	case "re_install_plugin":
		ReInstall(jsonData.Content)
	case "re_check_plugin":
		ReCheck(jsonData.Content)
	case "uninstall_plugin":
		Uninstall(jsonData.Content)
	case "UpdateSystem":
		SystemUpdate(jsonData.Content)
	case "restart":
		// 不能直接 os.Exit(0)：服务端在改配置（扫描模板/字典/项目）时会广播 restart，
		// 而这时节点很可能正在跑任务——硬退出等于把那条扫描腰斩。
		// 2026-11-26 实测两次：felix 与 superdrug 的目录扫描都在跑到一半时被配置更新打断，
		// 任务停留在 status=1，最后变成「没人跑的幽灵任务」。
		// 改成等当前任务结束再退出；等太久（默认 30 分钟）也要退，否则新配置永远不生效。
		go gracefulRestart(jsonData.Content)
	}
}

// gracefulRestart 等手头的任务跑完再退出，最多等 TASK_RESTART_GRACE_SEC（默认 1800 秒）。
// 参数是服务端附带的原因，只用于日志。
func gracefulRestart(reason string) {
	grace := 1800
	if v := strings.TrimSpace(os.Getenv("TASK_RESTART_GRACE_SEC")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			grace = n
		}
	}
	if grace == 0 {
		logger.SlogInfoLocal("config restart: grace disabled, exiting now (" + reason + ")")
		os.Exit(0)
	}
	deadline := time.Now().Add(time.Duration(grace) * time.Second)
	logger.SlogInfoLocal(fmt.Sprintf("config restart requested (%s): 等待当前任务结束，最多 %ds", reason, grace))
	for time.Now().Before(deadline) {
		running, _ := handler.TaskHandle.GetRunFin()
		if running <= 0 {
			logger.SlogInfoLocal("config restart: no running task, exiting")
			os.Exit(0)
		}
		time.Sleep(10 * time.Second)
	}
	logger.SlogWarnLocal(fmt.Sprintf("config restart: 等待超时（%ds）仍有用例在跑，强制退出", grace))
	os.Exit(0)
}

func RefreshConfig() {
	ticker := time.Tick(3 * time.Second)
	for {
		<-ticker
		RefreshConfigNodeName := "refresh_config:" + global.AppConfig.NodeName
		exists, err := redis.RedisClient.Exists(context.Background(), RefreshConfigNodeName)
		if err != nil {
			logger.SlogError(fmt.Sprintf("RefreshConfig Error: %v", err))
			continue
		}
		if !exists {
			continue
		}
		listLength, err := redis.RedisClient.LLen(context.Background(), RefreshConfigNodeName)
		if err != nil {
			logger.SlogError(fmt.Sprintf("RefreshConfig Error getting list length: %v", err))
			continue
		}
		if listLength == 0 {
			continue
		}
		msgs, err := redis.RedisClient.BatchGetAndDelete(context.Background(), RefreshConfigNodeName, listLength)
		if err != nil {
			logger.SlogErrorLocal(fmt.Sprintf("RefreshConfig Error batch get: %v", err))
			continue
		}

		var pocAddIDs, pocDeleteIDs []string
		var needUpdateFinger bool

		for _, msg := range msgs {
			logger.SlogInfo(fmt.Sprintf("recv RefreshConfig: %s", msg))
			jsonData := Message{}
			err2 := json.Unmarshal([]byte(msg), &jsonData)
			if err2 != nil {
				logger.SlogErrorLocal(fmt.Sprintf("Task parse error: %v", err))
				continue
			}
			if jsonData.Name != "all" && jsonData.Name != global.AppConfig.NodeName {
				continue
			}
			switch jsonData.Type {
			case "poc":
				addIDs, deleteIDs := parsePocContent(jsonData.Content)
				pocAddIDs = append(pocAddIDs, addIDs...)
				pocDeleteIDs = append(pocDeleteIDs, deleteIDs...)
			case "finger":
				needUpdateFinger = true
			default:
				handleRefreshConfigMessage(jsonData)
			}
		}

		if len(pocDeleteIDs) > 0 {
			UpdatePoc("delete:" + strings.Join(uniqueStrings(pocDeleteIDs), ","))
		}
		if len(pocAddIDs) > 0 {
			UpdatePoc("add:" + strings.Join(uniqueStrings(pocAddIDs), ","))
		}
		if needUpdateFinger {
			UpdateWebFinger()
		}
	}
}
