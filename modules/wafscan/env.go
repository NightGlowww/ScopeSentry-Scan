package wafscan

import (
	"os"
	"strconv"
)

// envInt 读整数环境变量，缺省或非法时用默认值。
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
