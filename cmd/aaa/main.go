package main

import (
	"bufio"
	"container/heap"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var patterns = []LogPattern{
	{"/Users/rey/Desktop/wazuh-docker/russellmitchell_no-pcaps/gather/*/logs/auth.log*", "auth_log"},
	{"/Users/rey/Desktop/wazuh-docker/russellmitchell_no-pcaps/gather/*/logs/syslog*", "syslog"},
	{"/Users/rey/Desktop/wazuh-docker/russellmitchell_no-pcaps/gather/*/logs/apache2/*access.log*", "apache_access"},
	{"/Users/rey/Desktop/wazuh-docker/russellmitchell_no-pcaps/gather/*/logs/suricata/eve.json", "suricata"},
	{"/Users/rey/Desktop/wazuh-docker/russellmitchell_no-pcaps/gather/*/logs/audit/audit.log*", "audit_log"},
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

func loadReplaySources() ([]ReplaySource, error) {
	var sources []ReplaySource

	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid glob pattern %s: %w", pattern.Pattern, err)
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
	mode := flag.String("mode", "detect", "Execution mode: file | neo4j | detect")
	outputFile := flag.String("output-file", defaultOutputFile, "Output JSONL filepath when -mode file")
	alertsFile := flag.String("alerts-file", "detection_alerts.jsonl", "Output JSONL filepath for detection alerts when -mode detect")
	minSeverity := flag.String("min-severity", "LOW", "Minimum severity level filter: LOW | MEDIUM | HIGH | CRITICAL")
	neo4jURL := flag.String("neo4j-url", defaultNeo4jURL, "Neo4j HTTP API base URL when -mode neo4j or detect")
	neo4jUser := flag.String("neo4j-user", defaultNeo4jUser, "Neo4j username")
	neo4jPass := flag.String("neo4j-pass", defaultNeo4jPass, "Neo4j password")
	rulesPath := flag.String("rules", "rules", "JSON Decision Tree rules file or directory path when -mode detect")
	rateLimit := flag.Float64("rate", defaultRate, "Maximum log events per second to process (replay speed limit)")

	flag.Parse()

	if *mode == "detect" {
		runDetectionMode(*rulesPath, *alertsFile, *minSeverity, *neo4jURL, *neo4jUser, *neo4jPass)
		return
	}

	sink, err := openEventSink(*mode, *outputFile, *neo4jURL, *neo4jUser, *neo4jPass)
	if err != nil {
		fmt.Printf("[!] Failed to initialize sink: %v\n", err)
		os.Exit(1)
	}

	sources, err := loadReplaySources()
	if err != nil {
		fmt.Printf("[!] Failed to load replay sources: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("[+] Loaded %d log files across replay sources.\n", len(sources))

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
			fmt.Printf("[*] Processed %d log events into provenance graph...\n", processedCount)
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

	fmt.Printf("[+] Finished processing %d log events. Mode: %s\n", processedCount, *mode)
}
