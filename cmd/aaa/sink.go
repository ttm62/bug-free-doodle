package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

type neo4jStatement struct {
	Statement  string                 `json:"statement"`
	Parameters map[string]interface{} `json:"parameters"`
}

type neo4jTxRequest struct {
	Statements []neo4jStatement `json:"statements"`
}

type neo4jTxResponse struct {
	Errors []struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"errors"`
}

type neo4jSink struct {
	url       string
	user      string
	pass      string
	client    *http.Client
	buffer    []neo4jStatement
	batchSize int
	rateLimit time.Duration
	mu        sync.Mutex
}

func newNeo4jSink(url, user, pass string, rate float64) EventSink {
	var interval time.Duration
	if rate > 0 {
		interval = time.Duration(float64(time.Second) / rate)
	}

	sink := &neo4jSink{
		url:       url,
		user:      user,
		pass:      pass,
		client:    &http.Client{Timeout: 60 * time.Second},
		batchSize: 1000,
		rateLimit: interval,
	}

	sink.ensureSchemaIndexes()
	return sink
}

func (s *neo4jSink) ensureSchemaIndexes() {
	indexes := []string{
		"CREATE INDEX IF NOT EXISTS FOR (n:IPAddress) ON (n.id)",
		"CREATE INDEX IF NOT EXISTS FOR (n:Process) ON (n.id)",
		"CREATE INDEX IF NOT EXISTS FOR (n:File) ON (n.id)",
		"CREATE INDEX IF NOT EXISTS FOR (n:HTTPRequest) ON (n.id)",
		"CREATE INDEX IF NOT EXISTS FOR (n:User) ON (n.id)",
		"CREATE INDEX IF NOT EXISTS FOR (n:DNSQuery) ON (n.id)",
		"CREATE INDEX IF NOT EXISTS FOR (n:Alert) ON (n.id)",
	}

	var stmts []neo4jStatement
	for _, idx := range indexes {
		stmts = append(stmts, neo4jStatement{
			Statement:  idx,
			Parameters: map[string]interface{}{},
		})
	}

	reqBody := neo4jTxRequest{Statements: stmts}
	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return
	}

	endpoint := s.url + "/db/neo4j/tx/commit"
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s.user != "" && s.pass != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(s.user + ":" + s.pass))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	resp, err := s.client.Do(req)
	if err == nil {
		resp.Body.Close()
		fmt.Printf("[+] [Neo4j] Verified/Created schema indexes for high-speed replay.\n")
	}
}

func (s *neo4jSink) WriteEvent(event OutputEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.rateLimit > 0 {
		time.Sleep(s.rateLimit)
	}

	eventTS := event.Timestamp

	// 1. Merge Nodes with property updates
	for _, node := range event.Nodes {
		props := make(map[string]interface{})
		for k, v := range node.Properties {
			props[k] = v
		}
		props["id"] = node.ID

		stmt := fmt.Sprintf("MERGE (n:%s {id: $id}) SET n += $props", node.Label)
		s.buffer = append(s.buffer, neo4jStatement{
			Statement: stmt,
			Parameters: map[string]interface{}{
				"id":    node.ID,
				"props": props,
			},
		})
	}

	// 2. Merge Relationships with Weighted Temporal Aggregation (ON CREATE / ON MATCH)
	for _, rel := range event.Relationships {
		props := make(map[string]interface{})
		for k, v := range rel.Properties {
			props[k] = v
		}

		relTS := rel.Timestamp
		if relTS == "" {
			relTS = eventTS
		}

		stmt := fmt.Sprintf(
			"MERGE (a:%s {id: $from_id}) "+
				"MERGE (b:%s {id: $to_id}) "+
				"MERGE (a)-[r:%s]->(b) "+
				"ON CREATE SET r += $props, r.count = 1, r.first_seen = $ts, r.last_seen = $ts, r.timestamp = $ts "+
				"ON MATCH SET r.count = coalesce(r.count, 1) + 1, r.last_seen = $ts, r.timestamp = $ts",
			rel.FromLabel, rel.ToLabel, rel.Type,
		)
		s.buffer = append(s.buffer, neo4jStatement{
			Statement: stmt,
			Parameters: map[string]interface{}{
				"from_id": rel.FromID,
				"to_id":   rel.ToID,
				"props":   props,
				"ts":      relTS,
			},
		})
	}

	if len(s.buffer) >= s.batchSize {
		return s.flush()
	}
	return nil
}

func (s *neo4jSink) flush() error {
	if len(s.buffer) == 0 {
		return nil
	}

	reqBody := neo4jTxRequest{Statements: s.buffer}
	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	endpoint := s.url + "/db/neo4j/tx/commit"

	// Cơ chế Retry với Exponential Backoff khi gặp Deadlock (TransientError)
	maxRetries := 5
	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonBytes))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if s.user != "" && s.pass != "" {
			auth := base64.StdEncoding.EncodeToString([]byte(s.user + ":" + s.pass))
			req.Header.Set("Authorization", "Basic "+auth)
		}

		resp, err := s.client.Do(req)
		if err != nil {
			if attempt == maxRetries-1 {
				return fmt.Errorf("network error connecting to Neo4j at %s: %w", endpoint, err)
			}
			time.Sleep(time.Duration(100*(1<<attempt)) * time.Millisecond)
			continue
		}

		if resp.StatusCode == http.StatusNotFound {
			resp.Body.Close()
			endpointLegacy := s.url + "/db/data/transaction/commit"
			reqLegacy, errLeg := http.NewRequest("POST", endpointLegacy, bytes.NewBuffer(jsonBytes))
			if errLeg != nil {
				return errLeg
			}
			reqLegacy.Header.Set("Content-Type", "application/json")
			if s.user != "" && s.pass != "" {
				auth := base64.StdEncoding.EncodeToString([]byte(s.user + ":" + s.pass))
				reqLegacy.Header.Set("Authorization", "Basic "+auth)
			}
			resp, err = s.client.Do(reqLegacy)
			if err != nil {
				return fmt.Errorf("failed to connect to Neo4j legacy endpoint at %s: %w", s.url, err)
			}
			endpoint = endpointLegacy
		}

		bodyBytes, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("neo4j HTTP status %d for %s", resp.StatusCode, endpoint)
		}

		var txResp neo4jTxResponse
		if err := json.Unmarshal(bodyBytes, &txResp); err == nil {
			if len(txResp.Errors) > 0 {
				isTransient := strings.Contains(txResp.Errors[0].Code, "TransientError") || strings.Contains(txResp.Errors[0].Message, "Deadlock")
				if isTransient && attempt < maxRetries-1 {
					time.Sleep(time.Duration(150*(1<<attempt)) * time.Millisecond)
					continue
				}
				return fmt.Errorf("neo4j transaction error: %s - %s", txResp.Errors[0].Code, txResp.Errors[0].Message)
			}
		}

		break
	}

	s.buffer = s.buffer[:0]
	return nil
}

func (s *neo4jSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.flush()
}

type wazuhSyslogSink struct {
	addr      string
	conn      net.Conn
	rateLimit time.Duration
}

func newWazuhSyslogSink(addr string, rate float64) (EventSink, error) {
	if addr == "" {
		addr = "127.0.0.1:514"
	}
	conn, err := net.Dial("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Wazuh syslog on %s: %w", addr, err)
	}

	var interval time.Duration
	if rate > 0 {
		interval = time.Duration(float64(time.Second) / rate)
	}

	return &wazuhSyslogSink{
		addr:      addr,
		conn:      conn,
		rateLimit: interval,
	}, nil
}

func (s *wazuhSyslogSink) WriteEvent(event OutputEvent) error {
	rawLog := event.RawLine
	if rawLog == "" {
		rawLog = event.Content
	}
	if rawLog == "" {
		return nil
	}

	_, err := s.conn.Write([]byte(rawLog + "\n"))
	if err != nil {
		return fmt.Errorf("failed to send syslog to Wazuh: %w", err)
	}

	if s.rateLimit > 0 {
		time.Sleep(s.rateLimit)
	}
	return nil
}

func (s *wazuhSyslogSink) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
