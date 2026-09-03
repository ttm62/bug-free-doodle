package main

import (
	"fmt"
	"strings"
	"time"
)

// parseSyslogLine phân tích log định dạng RFC 3164 thành các Node Process, Host và quan hệ RAN_ON.
// Ví dụ log: Jan 16 07:16:17 target-server systemd[1]: Stopping Apache HTTP Server...
func parseSyslogLine(input string) (ParsedLogLine, error) {
	if len(input) < 16 {
		return ParsedLogLine{}, fmt.Errorf("syslog line is too short")
	}

	ts, err := time.Parse("2006 Jan 2 15:04:05", "2022 "+input[:15])
	if err != nil {
		return ParsedLogLine{}, fmt.Errorf("failed to parse syslog timestamp: %w", err)
	}

	content := ""
	if len(input) > 16 {
		content = strings.TrimSpace(input[16:])
	}

	var nodes []Node
	var rels []Relationship

	parts := strings.Fields(content)
	if len(parts) >= 2 {
		hostname := parts[0]
		procPart := parts[1]

		procName := procPart
		pidStr := ""
		if idx := strings.IndexByte(procPart, '['); idx > 0 {
			procName = procPart[:idx]
			if endIdx := strings.IndexByte(procPart[idx+1:], ']'); endIdx > 0 {
				pidStr = procPart[idx+1 : idx+1+endIdx]
			}
		} else {
			procName = strings.TrimSuffix(procName, ":")
		}

		hostID := "host_" + hostname
		procID := fmt.Sprintf("proc_%s_%s", hostname, procName)
		if pidStr != "" {
			procID = fmt.Sprintf("proc_%s_%s", hostname, pidStr)
		}

		nodes = append(nodes,
			Node{
				ID:    hostID,
				Label: "Host",
				Properties: map[string]interface{}{
					"hostname": hostname,
				},
			},
			Node{
				ID:    procID,
				Label: "Process",
				Properties: map[string]interface{}{
					"exe": procName,
					"pid": pidStr,
				},
			},
		)

		rels = append(rels, Relationship{
			FromID:    procID,
			FromLabel: "Process",
			ToID:      hostID,
			ToLabel:   "Host",
			Type:      "RAN_ON",
			Properties: map[string]interface{}{
				"timestamp": ts.UTC().Format(time.RFC3339Nano),
			},
		})
	}

	return ParsedLogLine{
		Timestamp:     ts.UTC(),
		Content:       content,
		Nodes:         nodes,
		Relationships: rels,
	}, nil
}
