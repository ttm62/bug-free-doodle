package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

type WazuhArchiveInner struct {
	Timestamp string `json:"timestamp"`
	Location  string `json:"location"`
	FullLog   string `json:"full_log"`
}

type WazuhArchiveEvent struct {
	Message   WazuhArchiveInner `json:"message"`
	Timestamp string            `json:"timestamp"`
	Location  string            `json:"location"`
	FullLog   string            `json:"full_log"`
}

func runWebhookMode(port, scanInterval int, rulesPath, alertsFilePath, minSeverityFilter, neo4jURL, neo4jUser, neo4jPass string) {
	fmt.Printf("[*] Starting Webhook Mode on port %d\n", port)

	// Initialize Neo4j sink
	sink, err := openEventSink("neo4j", "", neo4jURL, neo4jUser, neo4jPass, "", 0)
	if err != nil {
		log.Fatalf("[!] Failed to connect to Neo4j: %v", err)
	}
	defer sink.Close()

	// Start background scanner
	go func() {
		ticker := time.NewTicker(time.Duration(scanInterval) * time.Second)
		defer ticker.Stop()
		fmt.Printf("[*] Background scanner started, interval: %ds\n", scanInterval)
		for range ticker.C {
			fmt.Printf("\n[*] [%s] Triggering periodic detection scan...\n", time.Now().Format(time.RFC3339))
			runDetectionMode(rulesPath, alertsFilePath, minSeverityFilter, neo4jURL, neo4jUser, neo4jPass, false)
		}
	}()

	// HTTP Handler
	http.HandleFunc("/raw_logs", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var events []WazuhArchiveEvent
		if err := json.NewDecoder(r.Body).Decode(&events); err != nil {
			http.Error(w, "Invalid JSON payload", http.StatusBadRequest)
			return
		}

		processed := 0
		for _, event := range events {
			location := event.Location
			if location == "" {
				location = event.Message.Location
			}

			logLine := event.FullLog
			if logLine == "" {
				logLine = event.Message.FullLog
			}

			timestampStr := event.Timestamp
			if timestampStr == "" {
				timestampStr = event.Message.Timestamp
			}

			if logLine == "" {
				continue
			}

			logType := detectLogType(location, logLine)
			if logType == "" {
				continue
			}

			parser := getParser(logType)
			if parser == nil {
				continue
			}

			parsed, err := parser(logLine)
			if err != nil {
				continue
			}

			if parsed.Timestamp.IsZero() && timestampStr != "" {
				if t, err := time.Parse(time.RFC3339Nano, timestampStr); err == nil {
					parsed.Timestamp = t
				}
			}

			outEvent := OutputEvent{
				Timestamp:     parsed.Timestamp.Format(time.RFC3339Nano),
				LogType:       logType,
				Path:          location,
				Content:       parsed.Content,
				Nodes:         parsed.Nodes,
				Relationships: parsed.Relationships,
			}

			if err := sink.WriteEvent(outEvent); err != nil {
				fmt.Printf("[!] Failed to write event to Neo4j: %v\n", err)
			} else {
				processed++
				fmt.Printf("[%s] [Webhook] Ingested log [%s]: %s\n", time.Now().Format("2006-01-02 15:04:05"), logType, logLine)
			}
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "{\"status\": \"ok\", \"processed\": %d}", processed)
	})

	addr := fmt.Sprintf(":%d", port)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func detectLogType(location, logLine string) string {
	loc := strings.ToLower(location)
	if strings.Contains(loc, "auth.log") {
		return "auth_log"
	}
	if strings.Contains(loc, "syslog") {
		return "syslog"
	}
	if strings.Contains(loc, "access.log") {
		return "apache_access"
	}
	if strings.Contains(loc, "eve.json") {
		return "suricata"
	}
	if strings.Contains(loc, "audit.log") {
		return "audit_log"
	}

	trimmed := strings.TrimSpace(logLine)
	if strings.HasPrefix(trimmed, "{") && strings.Contains(trimmed, `"event_type"`) {
		return "suricata"
	}
	if strings.HasPrefix(trimmed, "type=") || strings.Contains(trimmed, "audit(") {
		return "audit_log"
	}
	if strings.Contains(trimmed, "sshd[") || strings.Contains(trimmed, "sudo:") || strings.Contains(trimmed, "pam_unix") || strings.Contains(trimmed, "Accepted ") || strings.Contains(trimmed, "Failed password") {
		return "auth_log"
	}
	if strings.Contains(trimmed, "HTTP/1.") {
		return "apache_access"
	}
	if len(trimmed) > 15 && (trimmed[3] == ' ' || trimmed[3] == '-') {
		return "syslog"
	}

	return "syslog"
}
