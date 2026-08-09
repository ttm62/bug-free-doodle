package main

import (
	"bufio"
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

func loadReplaySources(workDir string, folder string) ([]ReplaySource, error) {
	var sources []ReplaySource

	for _, pattern := range patterns {
		globPattern := filepath.Join(workDir, folder, pattern.Pattern)
		matches, err := filepath.Glob(globPattern)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern %s: %w", globPattern, err)
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
			} else {
				src.File.Close()
			}
		}
	}

	return sources, nil
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
	mode := flag.String("mode", "detect", "Execution mode: file | neo4j | detect | webhook")
	outputFile := flag.String("output-file", defaultOutputFile, "Output JSONL filepath when -mode file")
	alertsFile := flag.String("alerts-file", "detection_alerts.jsonl", "Output JSONL filepath for detection alerts when -mode detect")
	minSeverity := flag.String("min-severity", "LOW", "Minimum severity level filter: LOW | MEDIUM | HIGH | CRITICAL")
	neo4jURL := flag.String("neo4j-url", defaultNeo4jURL, "Neo4j HTTP API base URL when -mode neo4j or detect")
	neo4jUser := flag.String("neo4j-user", defaultNeo4jUser, "Neo4j username")
	neo4jPass := flag.String("neo4j-pass", defaultNeo4jPass, "Neo4j password")
	rulesPath := flag.String("rules", "rules", "JSON Decision Tree rules file or directory path when -mode detect or webhook")
	rateLimit := flag.Float64("rate", defaultRate, "Maximum log events per second to process (replay speed limit)")
	webhookPort := flag.Int("webhook-port", 5050, "Port for webhook server when -mode webhook")
	scanInterval := flag.Int("scan-interval", 60, "Interval in seconds to run detection scan when -mode webhook")

	flag.Parse()

	if *mode == "detect" {
		runDetectionMode(*rulesPath, *alertsFile, *minSeverity, *neo4jURL, *neo4jUser, *neo4jPass)
		return
	}

	if *mode == "webhook" {
		runWebhookMode(*webhookPort, *scanInterval, *rulesPath, *alertsFile, *minSeverity, *neo4jURL, *neo4jUser, *neo4jPass)
		return
	}

	sink, err := openEventSink(*mode, *outputFile, *neo4jURL, *neo4jUser, *neo4jPass)
	if err != nil {
		fmt.Printf("[!] Failed to initialize sink: %v\n", err)
		os.Exit(1)
	}

	sources, err := loadReplaySources(*work_dir, *datasetFolder)
	if err != nil {
		fmt.Printf("[!] Failed to load replay sources: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Loaded %d log files across replay sources.\n", len(sources))

	startTime := time.Now()

	h := &EntryHeap{}
	heap.Init(h)

	for i := range sources {
		pushCurrentLine(&sources[i], i, h)
	}

	processedCount := 0
	var ticker *time.Ticker

	if *rateLimit > 0 {
		interval := time.Duration(float64(time.Second) / *rateLimit)
		if interval <= 0 {
			interval = time.Nanosecond
		}
		ticker = time.NewTicker(interval)
		defer ticker.Stop()
	}

	for h.Len() > 0 {
		if ticker != nil {
			<-ticker.C
		}

		entry := heap.Pop(h).(ReplayEntry)

		src := &sources[entry.SourceIndex]
		outEvent := OutputEvent{
			Timestamp:     entry.Timestamp.Format(time.RFC3339Nano),
			LogType:       src.LogType,
			Path:          src.Path,
			LineNo:        entry.LineNo,
			Content:       entry.Content,
			Nodes:         entry.Nodes,
			Relationships: entry.Relationships,
		}

		if err := sink.WriteEvent(outEvent); err != nil {
			fmt.Printf("[!] Sink write error: %v\n", err)
		}

		processedCount++
		if processedCount%2000 == 0 {
			fmt.Printf("[*] Processed %d log events into provenance graph... (Elapsed: %v)\n", processedCount, time.Since(startTime))
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
}
