package main

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

var (
	reAccepted      = regexp.MustCompile(`Accepted (?:password|publickey|keyboard-interactive) for (\S+) from (\S+) port (\d+)`)
	reFailed        = regexp.MustCompile(`(?:Failed (?:password|publickey|keyboard-interactive)|Invalid user) (?:for )?(\S+) from (\S+) port (\d+)`)
	reSudoCmd       = regexp.MustCompile(`sudo:\s+(\S+)\s+:.*USER=(\S+)\s+;\s+COMMAND=(.+)`)
	reSessionOpened = regexp.MustCompile(`pam_unix\(\S+:session\): session opened for user (\S+)(?: by (\S+))?`)
	reSuCmd         = regexp.MustCompile(`su\[\d+\]:\s+Successful su for (\S+) by (\S+)`)
)

func parseAuthLogLine(input string) (ParsedLogLine, error) {
	if len(input) < 16 {
		return ParsedLogLine{}, fmt.Errorf("auth.log line is too short")
	}

	ts, err := time.Parse("2006 Jan 2 15:04:05", "2022 "+input[:15])
	if err != nil {
		return ParsedLogLine{}, fmt.Errorf("failed to parse auth log timestamp: %w", err)
	}

	content := ""
	if len(input) > 16 {
		content = strings.TrimSpace(input[16:])
	}

	var nodes []Node
	var rels []Relationship

	parts := strings.Fields(content)
	hostname := ""
	processName := ""
	pidStr := ""

	if len(parts) >= 2 {
		hostname = parts[0]
		procPart := parts[1]
		if idx := strings.IndexByte(procPart, '['); idx > 0 {
			processName = procPart[:idx]
			if endIdx := strings.IndexByte(procPart[idx+1:], ']'); endIdx > 0 {
				pidStr = procPart[idx+1 : idx+1+endIdx]
			}
		} else {
			processName = strings.TrimSuffix(procPart, ":")
		}
	}

	if hostname != "" {
		nodes = append(nodes, Node{
			ID:    "host_" + hostname,
			Label: "Host",
			Properties: map[string]interface{}{
				"hostname": hostname,
			},
		})
	}

	procID := ""
	if processName != "" {
		if pidStr != "" {
			procID = fmt.Sprintf("proc_%s_%s", hostname, pidStr)
		} else {
			procID = fmt.Sprintf("proc_%s_%s", hostname, processName)
		}
		nodes = append(nodes, Node{
			ID:    procID,
			Label: "Process",
			Properties: map[string]interface{}{
				"exe": processName,
				"pid": pidStr,
			},
		})

		if hostname != "" {
			rels = append(rels, Relationship{
				FromID:    procID,
				FromLabel: "Process",
				ToID:      "host_" + hostname,
				ToLabel:   "Host",
				Type:      "RAN_ON",
				Properties: map[string]interface{}{
					"timestamp": ts.UTC().Format(time.RFC3339Nano),
				},
			})
		}
	}

	// Case 1: Accepted login (password / publickey / keyboard-interactive)
	if matches := reAccepted.FindStringSubmatch(content); len(matches) == 4 {
		username := matches[1]
		ipAddr := matches[2]
		port := matches[3]

		userID := "user_" + username
		ipID := "ip_" + ipAddr

		nodes = append(nodes,
			Node{
				ID:    userID,
				Label: "User",
				Properties: map[string]interface{}{
					"username": username,
				},
			},
			Node{
				ID:    ipID,
				Label: "IPAddress",
				Properties: map[string]interface{}{
					"ip": ipAddr,
				},
			},
		)

		if hostname != "" {
			rels = append(rels, Relationship{
				FromID:    userID,
				FromLabel: "User",
				ToID:      "host_" + hostname,
				ToLabel:   "Host",
				Type:      "AUTHENTICATED_ON",
				Timestamp: ts.UTC().Format(time.RFC3339Nano),
				Properties: map[string]interface{}{
					"status":    "success",
					"timestamp": ts.UTC().Format(time.RFC3339Nano),
				},
			})
		}

		if procID != "" {
			rels = append(rels, Relationship{
				FromID:    procID,
				FromLabel: "Process",
				ToID:      ipID,
				ToLabel:   "IPAddress",
				Type:      "CONNECTED",
				Timestamp: ts.UTC().Format(time.RFC3339Nano),
				Properties: map[string]interface{}{
					"dst_port":  port,
					"timestamp": ts.UTC().Format(time.RFC3339Nano),
				},
			})
		}
	}

	// Case 2: Failed login (password / publickey / invalid user)
	if matches := reFailed.FindStringSubmatch(content); len(matches) == 4 {
		username := matches[1]
		ipAddr := matches[2]

		userID := "user_" + username
		ipID := "ip_" + ipAddr

		nodes = append(nodes,
			Node{
				ID:    userID,
				Label: "User",
				Properties: map[string]interface{}{
					"username": username,
				},
			},
			Node{
				ID:    ipID,
				Label: "IPAddress",
				Properties: map[string]interface{}{
					"ip": ipAddr,
				},
			},
		)

		rels = append(rels, Relationship{
			FromID:    userID,
			FromLabel: "User",
			ToID:      ipID,
			ToLabel:   "IPAddress",
			Type:      "AUTHENTICATED_ON",
			Timestamp: ts.UTC().Format(time.RFC3339Nano),
			Properties: map[string]interface{}{
				"status":    "failed",
				"timestamp": ts.UTC().Format(time.RFC3339Nano),
			},
		})
	}

	// Case 3: Sudo command execution
	if matches := reSudoCmd.FindStringSubmatch(content); len(matches) == 4 {
		invoker := matches[1]
		targetUser := matches[2]
		cmd := matches[3]

		invokerID := "user_" + invoker
		targetUserID := "user_" + targetUser

		nodes = append(nodes,
			Node{
				ID:    invokerID,
				Label: "User",
				Properties: map[string]interface{}{
					"username": invoker,
				},
			},
			Node{
				ID:    targetUserID,
				Label: "User",
				Properties: map[string]interface{}{
					"username": targetUser,
				},
			},
		)

		if procID != "" {
			rels = append(rels,
				Relationship{
					FromID:    invokerID,
					FromLabel: "User",
					ToID:      procID,
					ToLabel:   "Process",
					Type:      "RAN_AS",
					Timestamp: ts.UTC().Format(time.RFC3339Nano),
					Properties: map[string]interface{}{
						"is_sudo":     true,
						"command":     cmd,
						"target_user": targetUser,
						"timestamp":   ts.UTC().Format(time.RFC3339Nano),
					},
				},
				Relationship{
					FromID:    procID,
					FromLabel: "Process",
					ToID:      targetUserID,
					ToLabel:   "User",
					Type:      "SPAWNED",
					Timestamp: ts.UTC().Format(time.RFC3339Nano),
					Properties: map[string]interface{}{
						"command":   cmd,
						"timestamp": ts.UTC().Format(time.RFC3339Nano),
					},
				},
			)
		}
	}

	// Case 4: PAM session opened
	if matches := reSessionOpened.FindStringSubmatch(content); len(matches) >= 2 {
		targetUser := matches[1]
		userID := "user_" + targetUser
		nodes = append(nodes, Node{
			ID:    userID,
			Label: "User",
			Properties: map[string]interface{}{
				"username": targetUser,
			},
		})
		if procID != "" {
			rels = append(rels, Relationship{
				FromID:    procID,
				FromLabel: "Process",
				ToID:      userID,
				ToLabel:   "User",
				Type:      "RAN_AS",
				Timestamp: ts.UTC().Format(time.RFC3339Nano),
				Properties: map[string]interface{}{
					"timestamp": ts.UTC().Format(time.RFC3339Nano),
				},
			})
		}
	}

	// Case 5: su command
	if matches := reSuCmd.FindStringSubmatch(content); len(matches) == 3 {
		targetUser := matches[1]
		invoker := matches[2]
		
		invokerID := "user_" + invoker
		targetUserID := "user_" + targetUser
		
		nodes = append(nodes,
			Node{
				ID:    invokerID,
				Label: "User",
				Properties: map[string]interface{}{
					"username": invoker,
				},
			},
			Node{
				ID:    targetUserID,
				Label: "User",
				Properties: map[string]interface{}{
					"username": targetUser,
				},
			},
		)

		if procID != "" {
			rels = append(rels,
				Relationship{
					FromID:    invokerID,
					FromLabel: "User",
					ToID:      procID,
					ToLabel:   "Process",
					Type:      "RAN_AS",
					Timestamp: ts.UTC().Format(time.RFC3339Nano),
					Properties: map[string]interface{}{
						"is_su":       true,
						"target_user": targetUser,
						"timestamp":   ts.UTC().Format(time.RFC3339Nano),
					},
				},
			)
		}
	}

	return ParsedLogLine{
		Timestamp:     ts.UTC(),
		Content:       content,
		Nodes:         nodes,
		Relationships: rels,
	}, nil
}
