package results

import "testing"

func TestClassifyLeak(t *testing.T) {
	cases := []struct {
		url   string
		want  string
		hit   bool
	}{
		{"https://a.example.com/.env", "环境变量文件", true},
		{"https://a.example.com/.git/config", "版本库元数据", true},
		{"https://a.example.com/backup/db.sql", "数据库导出", true},
		{"https://a.example.com/www.zip", "备份/压缩包", true},
		{"https://a.example.com/.ssh/id_rsa", "私钥/凭据", true},
		{"https://a.example.com/", "", false},
		{"https://a.example.com/index.html", "", false},
		{"https://a.example.com/api/v1/users", "", false},
		{"https://a.example.com/login.php", "", false},
	}
	for _, c := range cases {
		kind, hit := ClassifyLeak(c.url)
		if hit != c.hit || kind != c.want {
			t.Fatalf("ClassifyLeak(%q) = (%q,%v), want (%q,%v)", c.url, kind, hit, c.want, c.hit)
		}
	}
}
