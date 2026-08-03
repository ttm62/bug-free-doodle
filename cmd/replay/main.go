package main

import (
	"bufio"
	"container/heap"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type ParsedLogLine struct {
	timestamp time.Time
	content   string
}

type ReplayEntry struct {
	timestamp   time.Time
	sourceIndex int
	lineNo      int
	content     string
}

type OutputEvent struct {
	Timestamp string `json:"timestamp"`
	LogType   string `json:"log_type"`
	Path      string `json:"path"`
	LineNo    int    `json:"line_no"`
	Content   string `json:"content"`
}

type LogParser func(string) (ParsedLogLine, error)

type LogPattern struct {
	pattern  string
	log_type string
}

type ReplaySource struct {
	path           string
	log_type       string
	parser         LogParser
	file           *os.File
	scanner        *bufio.Scanner
	currentLine    string
	hasCurrentLine bool
	lineNo         int
}

const (
	defaultOutputMode = "file"
	defaultOutputFile = "replay.jsonl"
)

const defaultOutputAddress = "127.0.0.1:9000"
const defaultRate = 100.0

type outputSink struct {
	writer    *bufio.Writer
	encoder   *json.Encoder
	closeFunc func() error
}

func (sink *outputSink) write(event OutputEvent) error {
	if err := sink.encoder.Encode(event); err != nil {
		return err
	}
	return sink.writer.Flush()
}

func (sink *outputSink) close() error {
	if sink == nil || sink.closeFunc == nil {
		return nil
	}
	return sink.closeFunc()
}

// ---- Min-Heap ----
type EntryHeap []ReplayEntry

func (h EntryHeap) Len() int { return len(h) }
func (h EntryHeap) Less(i, j int) bool {
	// Ưu tiên so sánh Timestamp, sau đó đến SourceIndex và LineNo giống hệt Nim
	if !h[i].timestamp.Equal(h[j].timestamp) {
		return h[i].timestamp.Before(h[j].timestamp)
	}
	if h[i].sourceIndex != h[j].sourceIndex {
		return h[i].sourceIndex < h[j].sourceIndex
	}
	return h[i].lineNo < h[j].lineNo
}
func (h EntryHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *EntryHeap) Push(x interface{}) { *h = append(*h, x.(ReplayEntry)) }
func (h *EntryHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}

func parseSyslogLikeLine(input string) (ParsedLogLine, error) {
	if len(input) < 16 {
		return ParsedLogLine{}, fmt.Errorf("syslog/auth line is too short")
	}
	// "2006 Jan 2 15:04:05" là format chuẩn của Go
	ts, err := time.Parse("2006 Jan 2 15:04:05", "2022 "+input[:15])
	if err != nil {
		return ParsedLogLine{}, err
	}
	content := ""
	if len(input) > 16 {
		content = input[16:]
	}
	return ParsedLogLine{timestamp: ts.UTC(), content: content}, nil
}

func parseApacheAccessLine(input string) (ParsedLogLine, error) {
	openBracket := strings.IndexByte(input, '[')
	closeBracket := strings.IndexByte(input[openBracket+1:], ']')
	if openBracket < 0 || closeBracket < 0 {
		return ParsedLogLine{}, fmt.Errorf("apache access line has no timestamp")
	}
	closeBracket += openBracket + 1

	timestampText := input[openBracket+1 : closeBracket]
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", timestampText)
	if err != nil {
		return ParsedLogLine{}, err
	}

	prefix := strings.TrimSpace(input[:openBracket])
	suffix := ""
	if closeBracket+1 < len(input) {
		suffix = strings.TrimLeft(input[closeBracket+1:], " ")
	}

	content := ""
	if len(prefix) > 0 && len(suffix) > 0 {
		content = prefix + " " + suffix
	} else if len(prefix) > 0 {
		content = prefix
	} else {
		content = suffix
	}
	return ParsedLogLine{timestamp: ts.UTC(), content: content}, nil
}

func parseAuditLine(input string) (ParsedLogLine, error) {
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
		return ParsedLogLine{}, err
	}

	// Convert float epoch to seconds and nanoseconds
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
	return ParsedLogLine{timestamp: ts, content: content}, nil
}

func parseSuricataLine(input string) (ParsedLogLine, error) {
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(input), &event); err != nil {
		return ParsedLogLine{}, err
	}

	tsStr, ok := event["timestamp"].(string)
	if !ok {
		return ParsedLogLine{}, fmt.Errorf("suricata event has no timestamp")
	}

	ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", tsStr)
	if err != nil {
		return ParsedLogLine{}, err
	}

	delete(event, "timestamp")
	contentBytes, _ := json.Marshal(event)

	return ParsedLogLine{timestamp: ts.UTC(), content: string(contentBytes)}, nil
}

var patterns = []LogPattern{
	{"/Users/rey/Desktop/wazuh-docker/russellmitchell_no-pcaps/gather/*/logs/auth.log*", "auth_log"},
	// {"/Users/rey/Desktop/wazuh-docker/russellmitchell_no-pcaps/gather/*/logs/syslog*", "syslog"},
	// {"/Users/rey/Desktop/wazuh-docker/russellmitchell_no-pcaps/gather/*/logs/apache2/*access.log*", "apache_access"},
	// {"/Users/rey/Desktop/wazuh-docker/russellmitchell_no-pcaps/gather/*/logs/suricata/eve.json", "suricata"},
	// {"/Users/rey/Desktop/wazuh-docker/russellmitchell_no-pcaps/gather/*/logs/audit/audit.log*", "audit_log"},
}

func getParser(logType string) LogParser {
	switch logType {
	case "auth_log", "syslog":
		return parseSyslogLikeLine
	case "apache_access":
		return parseApacheAccessLine
	case "suricata":
		return parseSuricataLine
	case "audit_log":
		return parseAuditLine
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
	hasCurrentLine := scanner.Scan()
	currentLine := ""
	lineNo := 0
	if hasCurrentLine {
		currentLine = scanner.Text()
		lineNo = 1
	}

	return ReplaySource{
		path:           path,
		log_type:       logType,
		parser:         parser,
		file:           file,
		scanner:        scanner,
		currentLine:    currentLine,
		hasCurrentLine: hasCurrentLine,
		lineNo:         lineNo,
	}, nil
}

func advanceReplaySource(source *ReplaySource) {
	if !source.hasCurrentLine {
		return
	}
	source.hasCurrentLine = source.scanner.Scan()
	if source.hasCurrentLine {
		source.currentLine = source.scanner.Text()
		source.lineNo++
	}
}

func loadReplaySources() []ReplaySource {
	var sources []ReplaySource
	for _, entry := range patterns {
		parser := getParser(entry.log_type)
		matches, err := filepath.Glob(entry.pattern)
		if err != nil {
			continue
		}
		for _, match := range matches {
			src, err := openReplaySource(match, entry.log_type, parser)
			if err == nil {
				sources = append(sources, src)
			}
		}
	}
	return sources
}

func pushCurrentLine(sourceIndex int, sources []ReplaySource, h *EntryHeap) {
	source := sources[sourceIndex]
	if source.hasCurrentLine {
		parsed, err := source.parser(source.currentLine)
		if err == nil {
			heap.Push(h, ReplayEntry{
				timestamp:   parsed.timestamp,
				sourceIndex: sourceIndex,
				lineNo:      source.lineNo,
				content:     parsed.content,
			})
		}
	}
}

func parseArgs() (string, string, string, float64) {
	outputMode := flag.String("mode", defaultOutputMode, "output mode: file or vector")
	outputAddress := flag.String("output", defaultOutputAddress, "TCP address for Vector socket source")
	outputFile := flag.String("output-file", defaultOutputFile, "output file path for file mode")
	rate := flag.Float64("rate", defaultRate, "events per second")
	flag.Parse()

	if *outputMode != "file" && *outputMode != "vector" {
		panic("mode must be either file or vector")
	}
	if *rate <= 0 {
		panic("rate must be greater than zero")
	}

	return *outputMode, *outputAddress, *outputFile, *rate
}

func openOutputSink(mode, address, filePath string) (*outputSink, error) {
	switch mode {
	case "file":
		file, err := os.Create(filePath)
		if err != nil {
			return nil, err
		}
		writer := bufio.NewWriterSize(file, 64*1024)
		return &outputSink{
			writer:  writer,
			encoder: json.NewEncoder(writer),
			closeFunc: func() error {
				if err := writer.Flush(); err != nil {
					_ = file.Close()
					return err
				}
				return file.Close()
			},
		}, nil
	case "vector":
		conn, err := net.Dial("tcp", address)
		if err != nil {
			return nil, err
		}

		tcpConn, ok := conn.(*net.TCPConn)
		if !ok {
			conn.Close()
			return nil, fmt.Errorf("unable to open TCP connection to %s", address)
		}

		writer := bufio.NewWriterSize(tcpConn, 64*1024)
		return &outputSink{
			writer:  writer,
			encoder: json.NewEncoder(writer),
			closeFunc: func() error {
				if err := writer.Flush(); err != nil {
					_ = tcpConn.Close()
					return err
				}
				return tcpConn.Close()
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported output mode: %s", mode)
	}
}

func writeEvent(sink *outputSink, event OutputEvent) error {
	return sink.write(event)
}

func main() {
	outputMode, outputAddress, outputFile, rate := parseArgs()
	sources := loadReplaySources()

	// for _, s := range sources {
	// 	Println(BlueColor, s.path)
	// }
	// return

	defer func() {
		for _, src := range sources {
			src.file.Close()
		}
	}()

	h := &EntryHeap{}
	heap.Init(h)

	sink, err := openOutputSink(outputMode, outputAddress, outputFile)
	if err != nil {
		panic(err)
	}
	defer func() {
		if err := sink.close(); err != nil {
			panic(err)
		}
	}()

	interval := time.Duration(float64(time.Second) / rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for i := range sources {
		pushCurrentLine(i, sources, h)
	}

	for h.Len() > 0 {
		<-ticker.C
		entry := heap.Pop(h).(ReplayEntry)
		src := sources[entry.sourceIndex]

		event := OutputEvent{
			Timestamp: entry.timestamp.UTC().Format(time.RFC3339Nano),
			LogType:   src.log_type,
			Path:      src.path,
			LineNo:    entry.lineNo,
			Content:   entry.content,
		}

		if err := writeEvent(sink, event); err != nil {
			panic(err)
		}

		advanceReplaySource(&sources[entry.sourceIndex])
		pushCurrentLine(entry.sourceIndex, sources, h)
	}
	fmt.Println("done")
}
