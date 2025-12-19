package fix

import (
	"bytes"
	"fmt"
	"log"

	"gopkg.in/yaml.v3"
)

// ApplyMongoFix enforces desired MongoDB config values using map merge semantics.
func ApplyMongoFix(raw string) (string, bool, error) {
	var cfg map[string]interface{}
	if err := yaml.Unmarshal([]byte(raw), &cfg); err != nil {
		// If parsing fails, return the error for proper error handling.
		return raw, false, fmt.Errorf("failed to parse MongoDB config: %v", err)
	}

	// Initialize cfg if it's nil (empty YAML case)
	if cfg == nil {
		cfg = make(map[string]interface{})
	}

	// Desired updates (section -> key -> value) similar to MySQL patch map.
	patches := map[string]map[string]interface{}{
		"systemLog": {
			"logRotate": "rename",
		},
	}

	changed := false
	for section, kv := range patches {
		node, ok := cfg[section].(map[string]interface{})
		if !ok {
			node = map[string]interface{}{}
			cfg[section] = node
			changed = true
		}
		for key, val := range kv {
			if current, ok := node[key]; !ok || current != val {
				node[key] = val
				changed = true
			}
		}
	}
	if !changed {
		log.Printf("MongoDB config already up-to-date")
		return raw, false, nil
	}

	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return raw, false, fmt.Errorf("failed to encode MongoDB config: %v", err)
	}

	log.Printf("MongoDB configuration updated: set logRotate to 'rename'")
	return buf.String(), true, nil
}
