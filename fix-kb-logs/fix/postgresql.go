package fix

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"regexp"
	"strings"
)

// ApplyPostgreSQLFix updates postgresql.conf by enforcing PostgreSQL parameters.
func ApplyPostgreSQLFix(raw string) (string, bool, error) {
	desiredConfigs := map[string]string{
		"logging_collector": "true",
		"log_rotation_age":  "30min",
		"log_rotation_size": "0",
		"log_filename":      "postgresql.log",
		"log_destination":   "stderr",
	}

	// Parse postgresql.conf line by line
	var lines []string
	var missingParams []string
	changed := false

	// Regex to match configuration parameters: key = value
	configRegex := regexp.MustCompile(`^\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*=\s*(.+?)\s*$`)

	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := scanner.Text()
		lines = append(lines, line)

		matches := configRegex.FindStringSubmatch(line)
		if len(matches) == 3 {
			key := strings.TrimSpace(matches[1])
			currentValue := strings.TrimSpace(matches[2])

			if desiredValue, exists := desiredConfigs[key]; exists {
				// Remove surrounding quotes if present for comparison
				if strings.HasPrefix(currentValue, "'") && strings.HasSuffix(currentValue, "'") {
					currentValue = currentValue[1 : len(currentValue)-1]
				}
				if currentValue != desiredValue {
					// Replace the line with updated value
					lines[len(lines)-1] = fmt.Sprintf("%s = '%s'", key, desiredValue)
					changed = true
				}
				delete(desiredConfigs, key)
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return raw, false, fmt.Errorf("error reading postgresql.conf: %v", err)
	}

	// Check for missing parameters that need to be appended
	for key, value := range desiredConfigs {
		missingParams = append(missingParams, fmt.Sprintf("%s = '%s'", key, value))
		changed = true
	}

	if !changed {
		log.Printf("PostgreSQL config already up-to-date")
		return raw, false, nil
	}

	// Build the updated configuration
	var buf bytes.Buffer
	for _, line := range lines {
		buf.WriteString(line + "\n")
	}

	// Append missing parameters to the end
	if len(missingParams) > 0 {
		buf.WriteString("\n# PostgreSQL logging configuration (auto-generated)\n")
		for _, param := range missingParams {
			buf.WriteString(param + "\n")
		}
	}

	log.Printf("PostgreSQL configuration updated: added/modified %d parameters", len(missingParams)+1)
	return buf.String(), true, nil
}
