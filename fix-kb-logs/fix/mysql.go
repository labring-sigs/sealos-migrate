package fix

import (
	"bytes"

	"github.com/go-ini/ini"
)

// ApplyMySQLFix updates MySQL configuration text and reports whether anything changed.
func ApplyMySQLFix(raw string) (string, bool, error) {
	cfg, err := ini.LoadSources(ini.LoadOptions{}, []byte(raw))
	if err != nil {
		return "", false, err
	}

	patches := map[string]map[string]string{
		"mysqld": {
			"log_error":           "/data/mysql/log/mysqld-error.log",
			"slow_query_log":      "1",
			"slow_query_log_file": "/data/mysql/log/slow-query.log",
			"long_query_time":     "1",
		},
	}

	changed := false
	for section, kv := range patches {
		sec := cfg.Section(section)
		for key, val := range kv {
			if sec.Key(key).String() != val {
				sec.Key(key).SetValue(val)
				changed = true
			}
		}
	}

	if !changed {
		return raw, false, nil
	}

	var buf bytes.Buffer
	if _, err := cfg.WriteTo(&buf); err != nil {
		return "", false, err
	}
	return buf.String(), true, nil
}
