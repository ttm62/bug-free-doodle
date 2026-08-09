package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// WazuhArchiveEvent represents a log event received from Wazuh's archives.json via Vector
type WazuhArchiveEvent struct {
	Timestamp string `json:"timestamp"`
	Location  string `json:"location"`
	FullLog   string `json:"full_log"`
}

// runWebhookMode starts the HTTP server for Vector and the background scanner
func runWebhookMode(port, scanInterval int, rulesPath, alertsFilePath, minSeverityFilter, neo4jURL, neo4jUser, neo4jPass string) {
	fmt.Printf("[*] Starting Webhook Mode on port %d\n", port)
	
	// Initialize Neo4j sink
	sink, err := openEventSink("neo4j", "", neo4jURL, neo4jUser, neo4jPass)
	if err != nil {
		log.Fatalf("[!] Failed to connect to Neo4j: %v", err)
	}
	defer sink.Close()

	// Initialize the detector cache
	initAlertCache()

	// Start background scanner
	go func() {
		ticker := time.NewTicker(time.Duration(scanInterval) * time.Second)
		defer ticker.Stop()
		fmt.Printf("[*] Background scanner started, interval: %ds\n", scanInterval)
		for range ticker.C {
			fmt.Printf("\n[*] [%s] Triggering periodic detection scan...\n", time.Now().Format(time.RFC3339))
			runDetectionMode(rulesPath, alertsFilePath, minSeverityFilter, neo4jURL, neo4jUser, neo4jPass)
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
			logType := getLogTypeFromLocation(event.Location)
			if logType == "" {
				continue
			}

			parser := getParser(logType)
			if parser == nil {
				continue
			}

			// We use FullLog because that's usually the raw syslogged string
			// Some Wazuh logs might require custom parsing if FullLog is missing
			logLine := event.FullLog
			if logLine == "" {
				continue
			}

			parsed, err := parser(logLine)
			if err != nil {
				continue
			}

			// Use the Wazuh timestamp if available, fallback to parsed
			t, err := time.Parse(time.RFC3339Nano, event.Timestamp)
			if err == nil {
				parsed.Timestamp = t
			}

			outEvent := OutputEvent{
				Timestamp:     parsed.Timestamp.Format(time.RFC3339Nano),
				LogType:       logType,
				Path:          event.Location,
				Content:       parsed.Content,
				Nodes:         parsed.Nodes,
				Relationships: parsed.Relationships,
			}

			if err := sink.WriteEvent(outEvent); err != nil {
				fmt.Printf("[!] Failed to write event to Neo4j: %v\n", err)
			} else {
				processed++
			}
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "{\"status\": \"ok\", \"processed\": %d}", processed)
	})

	addr := fmt.Sprintf(":%d", port)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func getLogTypeFromLocation(location string) string {
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
	return ""
}
