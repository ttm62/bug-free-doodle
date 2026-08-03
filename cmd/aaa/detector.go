package main

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type RuleTree struct {
	ID        string      `json:"id"`
	Name      string      `json:"name"`
	Severity  string      `json:"severity"`
	EmitAlert *bool       `json:"emit_alert,omitempty"`
	Query     string      `json:"query"`
	OnMatch   MatchAction `json:"on_match"`
}

type MatchAction struct {
	AlertMessage string     `json:"alert_message"`
	Next         []RuleTree `json:"next"`
}

type DetectionRule struct {
	RuleID        string   `json:"rule_id"`
	RuleName      string   `json:"rule_name"`
	Enabled       bool     `json:"enabled"`
	TriggerSource string   `json:"trigger_source"`
	Tree          RuleTree `json:"tree"`
}

type DetectionAlert struct {
	Timestamp    string                 `json:"timestamp"`
	RuleID       string                 `json:"rule_id"`
	RuleName     string                 `json:"rule_name"`
	NodeID       string                 `json:"node_id"`
	NodeName     string                 `json:"node_name"`
	Severity     string                 `json:"severity"`
	Depth        int                    `json:"depth"`
	AlertMessage string                 `json:"alert_message"`
	Details      map[string]interface{} `json:"details"`
}

func getSeverityLevel(sev string) int {
	switch strings.ToUpper(sev) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	default:
		return 0
	}
}

func loadRulesFromPath(rulesPath string) ([]DetectionRule, error) {
	var rules []DetectionRule

	info, err := os.Stat(rulesPath)
	if err != nil {
		return nil, err
	}

	var files []string
	if info.IsDir() {
		entries, err := filepath.Glob(filepath.Join(rulesPath, "*.json"))
		if err != nil {
			return nil, err
		}
		files = entries
	} else {
		files = append(files, rulesPath)
	}

	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		var rule DetectionRule
		if err := json.Unmarshal(data, &rule); err == nil && rule.Enabled {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func runCypherQuery(url, user, pass, query string, params map[string]interface{}) ([]map[string]interface{}, error) {
	if params == nil {
		params = make(map[string]interface{})
	}
	stmt := neo4jStatement{
		Statement:  query,
		Parameters: params,
	}
	reqBody := neo4jTxRequest{Statements: []neo4jStatement{stmt}}
	jsonBytes, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}

	endpoint := url + "/db/neo4j/tx/commit"
	req, err := http.NewRequest("POST", endpoint, bytes.NewBuffer(jsonBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if user != "" && pass != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Authorization", "Basic "+auth)
	}

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var txResp struct {
		Results []struct {
			Columns []string `json:"columns"`
			Data    []struct {
				Row []interface{} `json:"row"`
			} `json:"data"`
		} `json:"results"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}

	if err := json.Unmarshal(bodyBytes, &txResp); err != nil {
		return nil, err
	}

	if len(txResp.Errors) > 0 {
		return nil, fmt.Errorf("cypher error: %s", txResp.Errors[0].Message)
	}

	var results []map[string]interface{}
	if len(txResp.Results) > 0 {
		cols := txResp.Results[0].Columns
		for _, dataRow := range txResp.Results[0].Data {
			rowMap := make(map[string]interface{})
			for i, col := range cols {
				if i < len(dataRow.Row) {
					rowMap[col] = dataRow.Row[i]
				}
			}
			results = append(results, rowMap)
		}
	}

	return results, nil
}

func formatAlertMessage(template string, row map[string]interface{}) string {
	msg := template
	for k, v := range row {
		placeholder := fmt.Sprintf("{%s}", k)
		valStr := fmt.Sprintf("%v", v)
		msg = strings.ReplaceAll(msg, placeholder, valStr)
	}
	return msg
}

func evaluateRuleTreeNode(url, user, pass string, rule DetectionRule, node RuleTree, parentParams map[string]interface{}, depth int, minSeverityLevel int, alertEncoder *json.Encoder, alertWriter *bufio.Writer) int {
	params := make(map[string]interface{})
	for k, v := range parentParams {
		params[k] = v
	}

	results, err := runCypherQuery(url, user, pass, node.Query, params)
	if err != nil {
		fmt.Printf("   [!] Depth %d [%s] Cypher error: %v\n", depth, node.ID, err)
		return 0
	}

	if len(results) == 0 {
		return 0
	}

	// Check if this node should emit alert (default true unless explicitly set to false)
	shouldEmit := true
	if node.EmitAlert != nil {
		shouldEmit = *node.EmitAlert
	}
	nodeSevLevel := getSeverityLevel(node.Severity)
	if nodeSevLevel < minSeverityLevel {
		shouldEmit = false
	}

	alertCount := 0
	indent := strings.Repeat("   ", depth-1)

	for _, row := range results {
		formattedMsg := formatAlertMessage(node.OnMatch.AlertMessage, row)

		if shouldEmit {
			alertCount++
			fmt.Printf("%s%s\n", indent, formattedMsg)

			if alertEncoder != nil {
				alertObj := DetectionAlert{
					Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
					RuleID:       rule.RuleID,
					RuleName:     rule.RuleName,
					NodeID:       node.ID,
					NodeName:     node.Name,
					Severity:     node.Severity,
					Depth:        depth,
					AlertMessage: formattedMsg,
					Details:      row,
				}
				_ = alertEncoder.Encode(alertObj)
				if alertWriter != nil {
					_ = alertWriter.Flush()
				}
			}
		}

		childParams := make(map[string]interface{})
		for k, v := range parentParams {
			childParams[k] = v
		}
		for k, v := range row {
			childParams[k] = v
		}

		for _, childNode := range node.OnMatch.Next {
			alertCount += evaluateRuleTreeNode(url, user, pass, rule, childNode, childParams, depth+1, minSeverityLevel, alertEncoder, alertWriter)
		}
	}
	return alertCount
}

func runDetectionMode(rulesPath, alertsFilePath, minSeverityFilter, neo4jURL, neo4jUser, neo4jPass string) {
	fmt.Printf("[*] Loading Detection Rules from: %s\n", rulesPath)
	rules, err := loadRulesFromPath(rulesPath)
	if err != nil {
		fmt.Printf("[!] Failed to load rules: %v\n", err)
		return
	}

	minSevLevel := getSeverityLevel(minSeverityFilter)

	var alertEncoder *json.Encoder
	var alertWriter *bufio.Writer
	var alertFile *os.File

	if alertsFilePath != "" {
		file, err := os.Create(alertsFilePath)
		if err != nil {
			fmt.Printf("[!] Failed to create alerts JSONL file %s: %v\n", alertsFilePath, err)
		} else {
			alertFile = file
			alertWriter = bufio.NewWriterSize(file, 64*1024)
			alertEncoder = json.NewEncoder(alertWriter)
			fmt.Printf("[+] Alerts will be saved to JSONL file: %s\n", alertsFilePath)
		}
	}

	fmt.Printf("[+] Loaded %d active JSON Decision Tree Rules. Minimum Severity Filter: %s\n\n", len(rules), strings.ToUpper(minSeverityFilter))

	totalAlerts := 0
	for i, rule := range rules {
		fmt.Printf("=========================================================================\n")
		fmt.Printf("[%d/%d] RUNNING RULE: %s (%s)\n", i+1, len(rules), rule.RuleName, rule.RuleID)
		fmt.Printf("=========================================================================\n")
		alertsFound := evaluateRuleTreeNode(neo4jURL, neo4jUser, neo4jPass, rule, rule.Tree, nil, 1, minSevLevel, alertEncoder, alertWriter)
		totalAlerts += alertsFound
		fmt.Println()
	}

	if alertFile != nil {
		_ = alertWriter.Flush()
		_ = alertFile.Close()
		fmt.Printf("[+] Successfully written alert results to JSONL file: %s\n", alertsFilePath)
	}

	fmt.Printf("[+] Finished executing all detection rules. Total alerts generated: %d\n", totalAlerts)
}
