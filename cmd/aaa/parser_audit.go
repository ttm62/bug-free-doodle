package main

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// isNoisyPath filters out benign system library, proc, sys, and cache files that create 80%+ graph bloat
func isNoisyPath(path string) bool {
	cleanPath := filepath.Clean(path)
	if cleanPath == "" || cleanPath == "." || cleanPath == "/" {
		return true
	}
	// Always KEEP security critical files
	if strings.Contains(cleanPath, "passwd") ||
		strings.Contains(cleanPath, "shadow") ||
		strings.Contains(cleanPath, "sudoers") ||
		strings.Contains(cleanPath, "authorized_keys") ||
		strings.Contains(cleanPath, "cron") ||
		strings.HasPrefix(cleanPath, "/tmp/") ||
		strings.HasPrefix(cleanPath, "/var/tmp/") ||
		strings.HasPrefix(cleanPath, "/dev/shm/") ||
		strings.HasPrefix(cleanPath, "/var/www/") ||
		strings.HasPrefix(cleanPath, "/home/") ||
		strings.HasPrefix(cleanPath, "/root/") {
		return false
	}
	// Filter out non-security noise
	return strings.HasPrefix(cleanPath, "/proc/") ||
		strings.HasPrefix(cleanPath, "/sys/") ||
		strings.HasPrefix(cleanPath, "/lib/") ||
		strings.HasPrefix(cleanPath, "/lib64/") ||
		strings.HasSuffix(cleanPath, ".so.cache") ||
		strings.HasSuffix(cleanPath, ".so") ||
		strings.HasPrefix(cleanPath, "/dev/null") ||
		strings.HasPrefix(cleanPath, "/dev/urandom") ||
		strings.HasPrefix(cleanPath, "/dev/random") ||
		strings.HasPrefix(cleanPath, "/var/log/journal/")
}

// decodeAuditdIPv4 decodes a hex-encoded sockaddr_in (AF_INET) from auditd
func decodeAuditdIPv4(saddr string) (string, string) {
	if len(saddr) < 16 {
		return "", ""
	}
	if !strings.HasPrefix(saddr, "0200") {
		return "", ""
	}

	// Ensure we only decode hex bytes
	hexPart := saddr[4:16]

	portHex1, err1 := strconv.ParseUint(hexPart[0:2], 16, 8)
	portHex2, err2 := strconv.ParseUint(hexPart[2:4], 16, 8)
	ipHex1, err3 := strconv.ParseUint(hexPart[4:6], 16, 8)
	ipHex2, err4 := strconv.ParseUint(hexPart[6:8], 16, 8)
	ipHex3, err5 := strconv.ParseUint(hexPart[8:10], 16, 8)
	ipHex4, err6 := strconv.ParseUint(hexPart[10:12], 16, 8)

	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || err5 != nil || err6 != nil {
		return "", ""
	}

	port := (int(portHex1) << 8) | int(portHex2)
	ip := fmt.Sprintf("%d.%d.%d.%d", ipHex1, ipHex2, ipHex3, ipHex4)
	return ip, strconv.Itoa(port)
}

// isBenignSystemProc checks if executable is a routine short-lived system daemon
func isBenignSystemProc(exe, comm string) bool {
	combined := strings.ToLower(exe + " " + comm)
	return strings.Contains(combined, "apparmor") ||
		strings.Contains(combined, "dhclient") ||
		strings.Contains(combined, "phpsessionclean") ||
		strings.Contains(combined, "dbus-daemon") ||
		strings.Contains(combined, "systemd-timesyncd") ||
		strings.Contains(combined, "systemd-resolved") ||
		strings.Contains(combined, "kworker") ||
		strings.Contains(combined, "auditd")
}

// parseKeyValueString parses auditd key=value pairs into a map
func parseKeyValueString(str string) map[string]string {
	res := make(map[string]string)
	inQuotes := false
	var key, val strings.Builder
	buildingKey := true

	for i := 0; i < len(str); i++ {
		ch := str[i]
		if ch == '=' && buildingKey {
			buildingKey = false
			continue
		}
		if ch == '"' {
			inQuotes = !inQuotes
			continue
		}
		if ch == ' ' && !inQuotes {
			if key.Len() > 0 {
				res[key.String()] = val.String()
				key.Reset()
				val.Reset()
				buildingKey = true
			}
			continue
		}
		if buildingKey {
			key.WriteByte(ch)
		} else {
			val.WriteByte(ch)
		}
	}
	if key.Len() > 0 {
		res[key.String()] = val.String()
	}
	return res
}

func parseAuditLogLine(input string) (ParsedLogLine, error) {
	auditStart := strings.Index(input, "audit(")
	if auditStart < 0 {
		return ParsedLogLine{}, fmt.Errorf("audit line has no epoch timestamp")
	}
	epochEnd := strings.IndexByte(input[auditStart+6:], ':')
	if epochEnd < 0 {
		return ParsedLogLine{}, fmt.Errorf("audit line has no epoch timestamp")
	}
	epochEnd += auditStart + 6

	epochText := input[auditStart+6 : epochEnd]
	epochFloat, err := strconv.ParseFloat(epochText, 64)
	if err != nil {
		return ParsedLogLine{}, fmt.Errorf("invalid epoch float: %w", err)
	}

	sec := int64(epochFloat)
	nsec := int64((epochFloat - float64(sec)) * 1e9)
	ts := time.Unix(sec, nsec).UTC()

	contentStart := strings.Index(input[auditStart:], "): ")
	content := input
	if contentStart >= 0 {
		contentStart += auditStart
		if contentStart+3 <= len(input) {
			content = input[contentStart+3:]
		}
	}

	auditType := ""
	if strings.HasPrefix(input, "type=") {
		if spaceIdx := strings.IndexByte(input, ' '); spaceIdx > 5 {
			auditType = input[5:spaceIdx]
		}
	}

	kv := parseKeyValueString(content)

	var nodes []Node
	var rels []Relationship

	pid := kv["pid"]
	ppid := kv["ppid"]
	exe := kv["exe"]
	comm := kv["comm"]
	uid := kv["uid"]
	auid := kv["auid"]
	name := kv["name"]
	syscall := kv["syscall"]
	unit := kv["unit"]

	if isBenignSystemProc(exe, comm) && auditType != "SERVICE_STOP" && auditType != "SERVICE_START" {
		// Drop this log line to reduce graph bloat
		return ParsedLogLine{}, nil
	}

	procID := ""
	if pid != "" {
		procID = "proc_" + pid

		procProps := map[string]interface{}{
			"pid":     pid,
			"ppid":    ppid,
			"exe":     exe,
			"comm":    comm,
			"syscall": syscall,
		}
		if auditType != "" {
			procProps["audit_type"] = auditType
		}
		if unit != "" {
			procProps["unit"] = unit
		}
		if auditType == "SERVICE_STOP" || auditType == "SERVICE_START" {
			procProps["is_service_event"] = true
		}

		nodes = append(nodes, Node{
			ID:         procID,
			Label:      "Process",
			Properties: procProps,
		})

		if ppid != "" && ppid != "0" {
			parentProcID := "proc_" + ppid
			nodes = append(nodes, Node{
				ID:    parentProcID,
				Label: "Process",
				Properties: map[string]interface{}{
					"pid": ppid,
				},
			})
			rels = append(rels, Relationship{
				FromID:    parentProcID,
				FromLabel: "Process",
				ToID:      procID,
				ToLabel:   "Process",
				Type:      "SPAWNED",
				Timestamp: ts.Format(time.RFC3339Nano),
			})
		}
	}

	effectiveUID := uid
	if effectiveUID == "" {
		effectiveUID = auid
	}
	if effectiveUID != "" && effectiveUID != "4294967295" {
		userID := "user_" + effectiveUID
		userName := "uid_" + effectiveUID
		if effectiveUID == "0" {
			userName = "root"
		}
		nodes = append(nodes, Node{
			ID:    userID,
			Label: "User",
			Properties: map[string]interface{}{
				"uid":           effectiveUID,
				"username":      userName,
				"is_privileged": (effectiveUID == "0"),
			},
		})
		if procID != "" {
			rels = append(rels, Relationship{
				FromID:    procID,
				FromLabel: "Process",
				ToID:      userID,
				ToLabel:   "User",
				Type:      "RAN_AS",
				Timestamp: ts.Format(time.RFC3339Nano),
			})
		}
	}

	if name != "" {
		cleanName := filepath.Clean(name)
		if !isNoisyPath(cleanName) {
			fileID := "file_" + cleanName
			nodes = append(nodes, Node{
				ID:    fileID,
				Label: "File",
				Properties: map[string]interface{}{
					"path":         cleanName,
					"is_sensitive": strings.Contains(cleanName, "shadow") || strings.Contains(cleanName, "passwd") || strings.Contains(cleanName, "sudoers") || strings.Contains(cleanName, "authorized_keys"),
				},
			})
			if procID != "" {
				relType := "READ"
				if syscall == "59" || syscall == "execve" {
					relType = "EXECUTED"
				} else if kv["success"] == "yes" && (strings.Contains(content, "write") || strings.Contains(content, "O_WRONLY") || strings.Contains(content, "O_RDWR") || strings.Contains(content, "create")) {
					relType = "WRITE"
				}
				rels = append(rels, Relationship{
					FromID:    procID,
					FromLabel: "Process",
					ToID:      fileID,
					ToLabel:   "File",
					Type:      relType,
					Timestamp: ts.Format(time.RFC3339Nano),
				})
			}
		}
	}

	// Parse network socket connections
	saddr := kv["saddr"]
	addr := kv["addr"]
	var targetIP, targetPort string
	if addr != "" && addr != "?" {
		targetIP = addr
		targetPort = kv["port"]
	} else if saddr != "" {
		targetIP, targetPort = decodeAuditdIPv4(saddr)
	}

	if targetIP != "" && targetIP != "0.0.0.0" && targetIP != "127.0.0.1" && procID != "" {
		ipNodeID := "ip_" + targetIP
		nodes = append(nodes, Node{
			ID:    ipNodeID,
			Label: "IPAddress",
			Properties: map[string]interface{}{
				"ip": targetIP,
			},
		})
		rels = append(rels, Relationship{
			FromID:    procID,
			FromLabel: "Process",
			ToID:      ipNodeID,
			ToLabel:   "IPAddress",
			Type:      "CONNECTED",
			Timestamp: ts.Format(time.RFC3339Nano),
			Properties: map[string]interface{}{
				"port": targetPort,
			},
		})
	}

	return ParsedLogLine{
		Timestamp:     ts,
		Content:       content,
		Nodes:         nodes,
		Relationships: rels,
	}, nil
}
