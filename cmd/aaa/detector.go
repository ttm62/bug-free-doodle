package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type AlertCacheEntry struct {
	LastSeen  time.Time
	LastCount float64
}

var (
	alertCache        map[string]AlertCacheEntry
	alertCacheMu      sync.RWMutex
	alertCacheTTL         = 24 * time.Hour
	alertCooldownSecs int = 0
)

// initAlertCache khởi tạo cache để loại bỏ cảnh báo trùng lặp và thiết lập thời gian cooldown.
func initAlertCache(cooldownSecs int) {
	alertCacheMu.Lock()
	defer alertCacheMu.Unlock()
	alertCache = make(map[string]AlertCacheEntry)
	alertCooldownSecs = cooldownSecs
}

// extractEventTime lấy thời điểm xảy ra sự kiện tấn công từ các trường chi tiết kết quả truy vấn Cypher.
// Ví dụ: tìm kiếm time_dnsteal, time_recon, time_privesc: 2022-01-24T13:50:40Z.
func extractEventTime(details map[string]interface{}) (time.Time, bool) {
	priorityKeys := []string{
		"time_dns", "time_dnsteal", "time_sudo", "time_su", "time_privesc",
		"time_rce", "time_revshell", "time_drop", "time_webshell",
		"time_recon", "time_wpcrack", "time_cracking", "time_post", "time_service_stop", "time_scan",
	}

	for _, pk := range priorityKeys {
		if v, ok := details[pk]; ok {
			if s, ok := v.(string); ok && len(s) >= 19 {
				clean := s
				if idx := strings.IndexByte(clean, '.'); idx > 0 {
					clean = clean[:idx]
				}
				if len(clean) >= 19 {
					if t, err := time.Parse("2006-01-02T15:04:05", clean[:19]); err == nil {
						return t, true
					}
				}
			}
		}
	}

	for _, v := range details {
		if s, ok := v.(string); ok && len(s) >= 19 {
			clean := s
			if idx := strings.IndexByte(clean, '.'); idx > 0 {
				clean = clean[:idx]
			}
			if len(clean) >= 19 {
				if t, err := time.Parse("2006-01-02T15:04:05", clean[:19]); err == nil {
					return t, true
				}
			}
		}
	}
	return time.Time{}, false
}

// extractMetricCount lấy số lượng tấn công || truy vấn || lỗi phục vụ ... dùng để tính tốc độ hoặc loại bỏ cảnh báo trùng lặp.
// Ví dụ: dns_count=1050, recon_count=85, fails=12.
func extractMetricCount(metricKey string, details map[string]interface{}) float64 {
	if metricKey != "" {
		if v, ok := details[metricKey]; ok {
			switch val := v.(type) {
			case float64:
				return val
			case int:
				return float64(val)
			case int64:
				return float64(val)
			case string:
				if f, err := strconv.ParseFloat(val, 64); err == nil {
					return f
				}
			}
		}
	}

	countKeys := []string{"dns_count", "req_count", "recon_count", "scan_count", "fails", "count", "queries"}
	for _, ck := range countKeys {
		if v, ok := details[ck]; ok {
			switch val := v.(type) {
			case float64:
				return val
			case int:
				return float64(val)
			case int64:
				return float64(val)
			case string:
				if f, err := strconv.ParseFloat(val, 64); err == nil {
					return f
				}
			}
		}
	}
	return 1.0
}

// generateAlertHash tạo khóa SHA-256 cho cảnh báo dựa trên RuleID, NodeID và các thuộc tính quan trọng.
// Bỏ qua các trường thời gian động để nhận diện chính xác các đợt tấn công lặp lại cùng một thực thể như IP, User, File.
func generateAlertHash(ruleID, nodeID string, node RuleTree, details map[string]interface{}) string {
	stableDetails := make(map[string]interface{})

	if len(node.EntityKeys) > 0 {
		for _, ek := range node.EntityKeys {
			if v, ok := details[ek]; ok {
				stableDetails[ek] = v
			}
		}
	} else {
		for k, v := range details {
			lowerK := strings.ToLower(k)
			if strings.HasPrefix(lowerK, "time") ||
				strings.Contains(lowerK, "_time") ||
				strings.Contains(lowerK, "timestamp") ||
				strings.Contains(lowerK, "last_seen") ||
				strings.Contains(lowerK, "first_seen") ||
				strings.Contains(lowerK, "count") ||
				strings.Contains(lowerK, "fails") ||
				strings.Contains(lowerK, "queries") {
				continue
			}
			stableDetails[k] = v
		}
	}

	b, _ := json.Marshal(stableDetails)
	hash := sha256.Sum256(b)
	return fmt.Sprintf("%s:%s:%x", ruleID, nodeID, hash)
}

// isDuplicateAlertNode kiểm tra cảnh báo có bị trùng lặp hay không dựa trên thời gian tĩnh Cooldown, ngưỡng MinVelocity, hoặc tỷ lệ MinGrowthRatio.
func isDuplicateAlertNode(hash string, node RuleTree, details map[string]interface{}) bool {
	if alertCache == nil {
		return false
	}

	eventTime, hasEventTime := extractEventTime(details)
	currentTime := time.Now()
	if hasEventTime {
		currentTime = eventTime
	}

	currentCount := extractMetricCount(node.RateMetric, details)

	alertCacheMu.RLock()
	entry, exists := alertCache[hash]
	alertCacheMu.RUnlock()

	if exists {
		// 1. Nếu đặt alertCooldownSecs <= 0: Loại bỏ cảnh báo lặp trên toàn tập alerts
		if alertCooldownSecs <= 0 {
			return true
		}

		diffTime := currentTime.Sub(entry.LastSeen)
		if diffTime < 0 {
			diffTime = -diffTime
		}

		// 1. Kiểm tra Cooldown
		if diffTime < time.Duration(alertCooldownSecs)*time.Second {
			return true
		}

		if node.MinVelocity > 0 && diffTime.Seconds() > 0 {
			deltaCount := currentCount - entry.LastCount
			if deltaCount < 0 {
				deltaCount = currentCount
			}
			velocityPerMin := (deltaCount / diffTime.Seconds()) * 60.0
			if velocityPerMin < node.MinVelocity && diffTime < 6*time.Hour {
				return true
			}
		}

		if node.MinGrowthRatio > 1.0 {
			if entry.LastCount > 0 && currentCount < (entry.LastCount*node.MinGrowthRatio) && diffTime < 6*time.Hour {
				return true
			}
		}
	}

	alertCacheMu.Lock()
	alertCache[hash] = AlertCacheEntry{
		LastSeen:  currentTime,
		LastCount: currentCount,
	}
	alertCacheMu.Unlock()
	return false
}

type RuleTree struct {
	ID             string      `json:"id"`
	Name           string      `json:"name"`
	Severity       string      `json:"severity"`
	EmitAlert      *bool       `json:"emit_alert,omitempty"`
	Query          string      `json:"query"`
	EntityKeys     []string    `json:"entity_keys,omitempty"`
	RateMetric     string      `json:"rate_metric,omitempty"`
	MinVelocity    float64     `json:"min_velocity,omitempty"`
	MinGrowthRatio float64     `json:"min_growth_ratio,omitempty"`
	OnMatch        MatchAction `json:"on_match"`
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

// loadRulesFromPath quét và đọc các quy tắc phát hiện từ đường dẫn.
func loadRulesFromPath(rulesPath string) ([]DetectionRule, error) {
	var rules []DetectionRule

	info, err := os.Stat(rulesPath)
	if err != nil {
		return nil, err
	}

	var filePaths []string
	if info.IsDir() {
		entries, err := os.ReadDir(rulesPath)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".json") {
				filePaths = append(filePaths, filepath.Join(rulesPath, e.Name()))
			}
		}
	} else {
		filePaths = append(filePaths, rulesPath)
	}

	for _, p := range filePaths {
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var ruleArray []DetectionRule
		if err := json.Unmarshal(data, &ruleArray); err == nil {
			for _, r := range ruleArray {
				if r.Enabled {
					rules = append(rules, r)
				}
			}
			continue
		}

		var rule DetectionRule
		if err := json.Unmarshal(data, &rule); err == nil && rule.Enabled {
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

// runCypherQuery thực thi truy vấn Cypher qua HTTP endpoint của Neo4j và trả kết quả dạng map.
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

	startQuery := time.Now()
	results, err := runCypherQuery(url, user, pass, node.Query, params)
	elapsedQuery := time.Since(startQuery)
	indent := strings.Repeat("   ", depth-1)

	if err != nil {
		fmt.Printf("%s[!] Depth %d [%s] Cypher error: %v\n", indent, depth, node.ID, err)
		return 0
	}

	fmt.Printf("%s[🕒 %v] Đã quét lớp: %s\n", indent, elapsedQuery.Round(time.Millisecond), node.Name)
	if f, err := os.OpenFile("query_stats.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644); err == nil {
		f.WriteString(fmt.Sprintf("[%s] RuleID: %s | Depth: %d | Node: %s | Time: %v\n", time.Now().Format(time.RFC3339), rule.RuleID, depth, node.Name, elapsedQuery.Round(time.Millisecond)))
		f.Close()
	}

	if len(results) == 0 {
		return 0
	}

	shouldEmit := true
	if node.EmitAlert != nil {
		shouldEmit = *node.EmitAlert
	}
	nodeSevLevel := getSeverityLevel(node.Severity)
	if nodeSevLevel < minSeverityLevel {
		shouldEmit = false
	}

	alertCount := 0

	for _, row := range results {
		fullDetails := make(map[string]interface{})
		for k, v := range parentParams {
			fullDetails[k] = v
		}
		for k, v := range row {
			fullDetails[k] = v
		}

		formattedMsg := formatAlertMessage(node.OnMatch.AlertMessage, fullDetails)

		if shouldEmit {
			alertHash := generateAlertHash(rule.RuleID, node.ID, node, fullDetails)
			if !isDuplicateAlertNode(alertHash, node, fullDetails) {
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
						Details:      fullDetails,
					}
					_ = alertEncoder.Encode(alertObj)
					if alertWriter != nil {
						_ = alertWriter.Flush()
					}
				}
			}
		}

		for _, childNode := range node.OnMatch.Next {
			alertCount += evaluateRuleTreeNode(url, user, pass, rule, childNode, fullDetails, depth+1, minSeverityLevel, alertEncoder, alertWriter)
		}
	}
	return alertCount
}

func runDetectionMode(rulesPath, alertsFilePath, minSeverityFilter, neo4jURL, neo4jUser, neo4jPass string, shouldLogResult bool) {
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
		file, err := os.OpenFile(alertsFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			fmt.Printf("[!] Failed to open alerts JSONL file %s: %v\n", alertsFilePath, err)
		} else {
			alertFile = file
			alertWriter = bufio.NewWriterSize(file, 64*1024)
			alertEncoder = json.NewEncoder(alertWriter)
			fmt.Printf("[+] Alerts will be saved (overwriting previous run) to JSONL file: %s\n", alertsFilePath)
		}
	}

	fmt.Printf("[+] Loaded %d active JSON Decision Tree Rules. Minimum Severity Filter: %s\n\n", len(rules), strings.ToUpper(minSeverityFilter))

	totalAlerts := 0
	for i, rule := range rules {
		if shouldLogResult {
			fmt.Printf("=========================================================================\n")
			fmt.Printf("[%d/%d] RUNNING RULE: %s (%s)\n", i+1, len(rules), rule.RuleName, rule.RuleID)
			fmt.Printf("=========================================================================\n")
		}

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
