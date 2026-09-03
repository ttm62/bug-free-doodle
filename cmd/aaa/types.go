package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

type Node struct {
	ID         string                 `json:"id"`
	Label      string                 `json:"label"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type Relationship struct {
	FromID     string                 `json:"from_id"`
	FromLabel  string                 `json:"from_label"`
	ToID       string                 `json:"to_id"`
	ToLabel    string                 `json:"to_label"`
	Type       string                 `json:"type"`
	Timestamp  string                 `json:"timestamp,omitempty"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type ParsedLogLine struct {
	Timestamp     time.Time
	Content       string
	Nodes         []Node
	Relationships []Relationship
}

type ReplayEntry struct {
	Timestamp     time.Time
	SourceIndex   int
	LineNo        int
	RawLine       string
	Content       string
	Nodes         []Node
	Relationships []Relationship
}

type OutputEvent struct {
	Timestamp     string         `json:"timestamp"`
	LogType       string         `json:"log_type"`
	Path          string         `json:"path"`
	LineNo        int            `json:"line_no"`
	RawLine       string         `json:"raw_line,omitempty"`
	Content       string         `json:"content"`
	Nodes         []Node         `json:"nodes,omitempty"`
	Relationships []Relationship `json:"relationships,omitempty"`
}

type LogParser func(string) (ParsedLogLine, error)

type LogPattern struct {
	Pattern string
	LogType string
}

type ReplaySource struct {
	Path           string
	LogType        string
	Parser         LogParser
	File           *os.File
	Scanner        *bufio.Scanner
	CurrentLine    string
	HasCurrentLine bool
	LineNo         int
}

const (
	defaultOutputMode = "file"
	defaultOutputFile = "replay.jsonl"
	defaultNeo4jURL   = "http://localhost:7474"
	defaultNeo4jUser  = "neo4j"
	defaultNeo4jPass  = "admin1234"
	defaultRate       = 100.0
)

type EventSink interface {
	WriteEvent(event OutputEvent) error
	Close() error
}

type fileSink struct {
	file      *os.File
	writer    *bufio.Writer
	encoder   *json.Encoder
	closeFunc func() error
}

func (s *fileSink) WriteEvent(event OutputEvent) error {
	if err := s.encoder.Encode(event); err != nil {
		return err
	}
	return s.writer.Flush()
}

func (s *fileSink) Close() error {
	if s == nil || s.closeFunc == nil {
		return nil
	}
	return s.closeFunc()
}

func openFileSink(filePath string) (EventSink, error) {
	file, err := os.Create(filePath)
	if err != nil {
		return nil, err
	}
	writer := bufio.NewWriterSize(file, 64*1024)
	return &fileSink{
		file:    file,
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
}

func openEventSink(mode, filePath, neo4jURL, neo4jUser, neo4jPass, wazuhAddr string, rate float64) (EventSink, error) {
	switch mode {
	case "file":
		return openFileSink(filePath)
	case "neo4j":
		return newNeo4jSink(neo4jURL, neo4jUser, neo4jPass, rate), nil
	case "wazuh":
		return newWazuhSyslogSink(wazuhAddr, rate)
	default:
		return nil, fmt.Errorf("unsupported mode '%s', must be 'file', 'neo4j', or 'wazuh'", mode)
	}
}

type EntryHeap []ReplayEntry

func (h EntryHeap) Len() int { return len(h) }
func (h EntryHeap) Less(i, j int) bool {
	if !h[i].Timestamp.Equal(h[j].Timestamp) {
		return h[i].Timestamp.Before(h[j].Timestamp)
	}
	if h[i].SourceIndex != h[j].SourceIndex {
		return h[i].SourceIndex < h[j].SourceIndex
	}
	return h[i].LineNo < h[j].LineNo
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
