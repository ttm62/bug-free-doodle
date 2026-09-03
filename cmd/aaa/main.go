package main

import (
	"bufio"
	"bytes"
	"container/heap"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

var patterns = []LogPattern{
	{"gather/*/logs/auth.log*", "auth_log"},
	{"gather/*/logs/syslog*", "syslog"},
	{"gather/*/logs/apache2/*access.log*", "apache_access"},
	{"gather/*/logs/suricata/eve.json", "suricata"},
	{"gather/*/logs/audit/audit.log*", "audit_log"},
}

func getParser(logType string) LogParser {
	switch logType {
	case "auth_log":
		return parseAuthLogLine
	case "syslog":
		return parseSyslogLine
	case "apache_access":
		return parseApacheAccessLogLine
	case "suricata":
		return parseSuricataLogLine
	case "audit_log":
		return parseAuditLogLine
	default:
		panic("unsupported log type: " + logType)
	}
}

func openReplaySource(path, logType string, parser LogParser) (ReplaySource, error) {
	file, err := os.Open(path)
	if err != nil {
		return ReplaySource{}, err
	}

	scanner := bufio.NewScanner(file)
	buf := make([]byte, 1024*1024)
	scanner.Buffer(buf, 10*1024*1024)

	hasCurrentLine := scanner.Scan()
	currentLine := ""
	lineNo := 0
	if hasCurrentLine {
		currentLine = scanner.Text()
		lineNo = 1
	}

	return ReplaySource{
		Path:           path,
		LogType:        logType,
		Parser:         parser,
		File:           file,
		Scanner:        scanner,
		CurrentLine:    currentLine,
		HasCurrentLine: hasCurrentLine,
		LineNo:         lineNo,
	}, nil
}

func advanceReplaySource(source *ReplaySource) {
	if !source.HasCurrentLine {
		return
	}
	source.HasCurrentLine = source.Scanner.Scan()
	if source.HasCurrentLine {
		source.CurrentLine = source.Scanner.Text()
		source.LineNo++
	}
}

func countLinesFast(filepath string) int {
	file, err := os.Open(filepath)
	if err != nil {
		return 0
	}
	defer file.Close()
	buf := make([]byte, 32*1024)
	count := 0
	lineSep := []byte{'\n'}
	for {
		c, err := file.Read(buf)
		count += bytes.Count(buf[:c], lineSep)
		if err != nil {
			break
		}
	}
	return count
}

func loadReplaySources(workDir string, folder string) ([]ReplaySource, int, error) {
	var sources []ReplaySource
	totalLines := 0

	for _, pattern := range patterns {
		globPattern := filepath.Join(workDir, folder, pattern.Pattern)
		matches, err := filepath.Glob(globPattern)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid glob pattern %s: %w", globPattern, err)
		}

		parser := getParser(pattern.LogType)

		for _, path := range matches {
			info, err := os.Stat(path)
			if err != nil || info.IsDir() {
				continue
			}

			src, err := openReplaySource(path, pattern.LogType, parser)
			if err != nil {
				fmt.Printf("[!] Warning: failed to open log file %s: %v\n", path, err)
				continue
			}

			if src.HasCurrentLine {
				sources = append(sources, src)
				totalLines += countLinesFast(path)
			} else {
				src.File.Close()
			}
		}
	}

	return sources, totalLines, nil
}

func pushCurrentLine(source *ReplaySource, sourceIndex int, heapObj *EntryHeap) {
	if !source.HasCurrentLine {
		return
	}

	parsed, err := source.Parser(source.CurrentLine)
	if err != nil {
		return
	}

	heap.Push(heapObj, ReplayEntry{
		Timestamp:     parsed.Timestamp,
		SourceIndex:   sourceIndex,
		LineNo:        source.LineNo,
		RawLine:       source.CurrentLine,
		Content:       parsed.Content,
		Nodes:         parsed.Nodes,
		Relationships: parsed.Relationships,
	})
}

func main() {
	dir, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	work_dir := flag.String("wd", dir, "Work dir")
	datasetFolder := flag.String("folder", "*", "Dataset folder name (default: * for all)")
	mode := flag.String("mode", "detect", "Execution mode: file | neo4j | detect | webhook | wazuh")
	outputFile := flag.String("output-file", defaultOutputFile, "Output JSONL filepath when -mode file")
	alertsFile := flag.String("alerts-file", "detection_alerts.jsonl", "Output JSONL filepath for detection alerts when -mode detect or webhook")
	minSeverity := flag.String("min-severity", "LOW", "Minimum severity level filter: LOW | MEDIUM | HIGH | CRITICAL")
	neo4jURL := flag.String("neo4j-url", defaultNeo4jURL, "Neo4j HTTP API base URL when -mode neo4j or detect")
	neo4jUser := flag.String("neo4j-user", defaultNeo4jUser, "Neo4j username")
	neo4jPass := flag.String("neo4j-pass", defaultNeo4jPass, "Neo4j password")
	rulesPath := flag.String("rules", "rules", "JSON Decision Tree rules file or directory path when -mode detect or webhook")
	webhookPort := flag.Int("webhook-port", 5050, "Port for webhook server when -mode webhook")
	scanInterval := flag.Int("scan-interval", 60, "Interval in seconds to run detection scan when -mode webhook")
	alertCooldown := flag.Int("alert-cooldown", 300, "Cooldown in seconds between repeated alerts for the same entity (0 = 24h dedup)")
	wazuhAddr := flag.String("wazuh-addr", "127.0.0.1:514", "Wazuh syslog UDP address (host:port) when -mode wazuh")
	rate := flag.Float64("rate", 0, "Rate limit in logs/sec when replaying logs (0 = unlimited)")

	skipEvents := flag.Int("skip", 0, "Number of log events to skip before processing")

	flag.Parse()

	if *mode == "detect" {
		initAlertCache(*alertCooldown)
		runDetectionMode(*rulesPath, *alertsFile, *minSeverity, *neo4jURL, *neo4jUser, *neo4jPass, true)
		return
	}

	if *mode == "webhook" {
		initAlertCache(*alertCooldown)
		runWebhookMode(*webhookPort, *scanInterval, *rulesPath, *alertsFile, *minSeverity, *neo4jURL, *neo4jUser, *neo4jPass)
		return
	}

	isStreamMode := (*mode == "stream")
	sinkMode := *mode
	if isStreamMode {
		sinkMode = "neo4j"
		initAlertCache(*alertCooldown)

		go func() {
			ticker := time.NewTicker(time.Duration(*scanInterval) * time.Second)
			defer ticker.Stop()
			fmt.Printf("[*] [Stream Mode] Background detector started, scanning every %ds (Alert cooldown: %ds)...\n", *scanInterval, *alertCooldown)
			for range ticker.C {
				fmt.Printf("\n[*] [%s] [Stream Mode] Triggering periodic detection scan...\n", time.Now().Format(time.RFC3339))
				runDetectionMode(*rulesPath, *alertsFile, *minSeverity, *neo4jURL, *neo4jUser, *neo4jPass, false)
			}
		}()
	}

	sink, err := openEventSink(sinkMode, *outputFile, *neo4jURL, *neo4jUser, *neo4jPass, *wazuhAddr, *rate)
	if err != nil {
		fmt.Printf("[!] Failed to initialize sink: %v\n", err)
		os.Exit(1)
	}

	sources, totalLines, err := loadReplaySources(*work_dir, *datasetFolder)
	if err != nil {
		fmt.Printf("[!] Failed to load replay sources: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Loaded %d log files (Total: %d lines) across replay sources.\n", len(sources), totalLines)

	startTime := time.Now()

	h := &EntryHeap{}
	heap.Init(h)

	for i := range sources {
		pushCurrentLine(&sources[i], i, h)
	}

	processedCount := 0

	for h.Len() > 0 {
		entry := heap.Pop(h).(ReplayEntry)
		src := &sources[entry.SourceIndex]

		processedCount++

		if processedCount <= *skipEvents {
			if processedCount%1000 == 0 {
				fmt.Print(".")
			}
			if processedCount == *skipEvents {
				fmt.Printf("\n[*] Finished skipping %d events.\n", *skipEvents)
			}
			advanceReplaySource(src)
			if src.HasCurrentLine {
				pushCurrentLine(src, entry.SourceIndex, h)
			} else {
				src.File.Close()
			}
			continue
		}

		outEvent := OutputEvent{
			Timestamp:     entry.Timestamp.Format(time.RFC3339Nano),
			LogType:       src.LogType,
			Path:          src.Path,
			LineNo:        entry.LineNo,
			RawLine:       entry.RawLine,
			Content:       entry.Content,
			Nodes:         entry.Nodes,
			Relationships: entry.Relationships,
		}

		if err := sink.WriteEvent(outEvent); err != nil {
			fmt.Printf("[!] Sink write error: %v\n", err)
		}

		if processedCount%2000 == 0 {
			var percentage float64
			if totalLines > 0 {
				percentage = float64(processedCount) / float64(totalLines) * 100.0
			}
			if *mode == "wazuh" {
				fmt.Printf("[*] Replayed %d log events to Wazuh (%s) (%.2f%%)... (Elapsed: %v)\n", processedCount, *wazuhAddr, percentage, time.Since(startTime))
			} else if isStreamMode {
				fmt.Printf("[*] [Stream] Processed %d log events into Neo4j graph (%.2f%%)... (Elapsed: %v)\n", processedCount, percentage, time.Since(startTime))
			} else {
				fmt.Printf("[*] Processed %d log events into provenance graph (%.2f%%)... (Elapsed: %v)\n", processedCount, percentage, time.Since(startTime))
			}
		}

		advanceReplaySource(src)
		if src.HasCurrentLine {
			pushCurrentLine(src, entry.SourceIndex, h)
		} else {
			src.File.Close()
		}
	}

	if err := sink.Close(); err != nil {
		fmt.Printf("[!] Sink close error: %v\n", err)
	}

	fmt.Printf("[+] Finished processing %d log events in %v. Mode: %s\n", processedCount, time.Since(startTime), *mode)

	if isStreamMode {
		fmt.Printf("\n[*] [Stream Mode] Final detection scan on completed graph...\n")
		runDetectionMode(*rulesPath, *alertsFile, *minSeverity, *neo4jURL, *neo4jUser, *neo4jPass, true)
	}
}
