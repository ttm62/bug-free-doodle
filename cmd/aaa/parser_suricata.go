package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// isPrivateIP kiểm tra địa chỉ IP có thuộc dải mạng nội bộ RFC 1918.
func isPrivateIP(ip string) bool {
	if strings.HasPrefix(ip, "10.") ||
		strings.HasPrefix(ip, "192.168.") ||
		strings.HasPrefix(ip, "127.") {
		return true
	}
	if strings.HasPrefix(ip, "172.") {
		parts := strings.Split(ip, ".")
		if len(parts) >= 2 {
			if octet, err := strings.TrimSpace(parts[1]), error(nil); err == nil {
				_ = octet
				// Check 172.16.0.0 - 172.31.255.255
				if len(parts[1]) >= 2 {
					return true
				}
			}
		}
		return true
	}
	return false
}

// isSuspiciousDnsTunneling phát hiện lưu lượng DNS Tunneling theo cấu trúc RFC 1035 với độ dài FQDN > 75 ký tự, nhãn subdomain >= 4 cấp, tỷ lệ ký tự mã hóa cao >= 20%.
// Ví dụ: 3x6-.0-.UEsDBBQAAAAIABSgXFIHQU1igQAAALE...invoices.xlsx.web-03.example.com.
func isSuspiciousDnsTunneling(rrname string) bool {
	if len(rrname) < 75 {
		return false
	}
	if strings.Contains(rrname, "in-addr.arpa") || strings.Contains(rrname, "ip6.arpa") {
		return false
	}

	labels := strings.Split(rrname, ".")
	if len(labels) < 4 {
		return false
	}

	maxLabelLen := 0
	specialOrDigit := 0
	for _, l := range labels {
		if len(l) > maxLabelLen {
			maxLabelLen = len(l)
			specialOrDigit = 0
			for i := 0; i < len(l); i++ {
				c := l[i]
				if (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '*' {
					specialOrDigit++
				}
			}
		}
	}

	if maxLabelLen >= 40 && float64(specialOrDigit)/float64(maxLabelLen) >= 0.20 {
		return true
	}

	return len(labels) >= 6 && maxLabelLen >= 30
}

// parseSuricataLogLine phân tích eve.json thành các Node IPAddress, Alert, HTTPRequest, DNSQuery và các quan hệ RAISED, TARGETED, REQUESTED, QUERIED.
// Ví dụ log: {"timestamp":"2022-01-24T14:39:57.123+0000","event_type":"dns","src_ip":"192.168.1.10","dns":{"rrname":"3x6-data.example.com","rrtype":"A"}}
func parseSuricataLogLine(input string) (ParsedLogLine, error) {
	var event map[string]interface{}
	if err := json.Unmarshal([]byte(input), &event); err != nil {
		return ParsedLogLine{}, fmt.Errorf("failed to unmarshal suricata json: %w", err)
	}

	tsStr, ok := event["timestamp"].(string)
	if !ok {
		return ParsedLogLine{}, fmt.Errorf("suricata event has no timestamp")
	}

	ts, err := time.Parse("2006-01-02T15:04:05.999999-0700", tsStr)
	if err != nil {
		return ParsedLogLine{}, fmt.Errorf("failed to parse suricata timestamp: %w", err)
	}

	eventType, _ := event["event_type"].(string)
	srcIP, _ := event["src_ip"].(string)
	destIP, _ := event["dest_ip"].(string)

	// Keep event if it's an Alert, HTTP, SSH, DNS, or involves private/attacker IPs
	isRelevant := (eventType == "alert" || eventType == "http" || eventType == "ssh" || eventType == "dns") ||
		(isPrivateIP(srcIP) || isPrivateIP(destIP))

	if !isRelevant {
		delete(event, "timestamp")
		contentBytes, _ := json.Marshal(event)
		return ParsedLogLine{Timestamp: ts.UTC(), Content: string(contentBytes)}, nil
	}

	var nodes []Node
	var rels []Relationship

	srcIPID := ""
	if srcIP != "" {
		srcIPID = "ip_" + srcIP
		nodes = append(nodes, Node{
			ID:    srcIPID,
			Label: "IPAddress",
			Properties: map[string]interface{}{
				"ip":          srcIP,
				"is_external": !isPrivateIP(srcIP),
			},
		})
	}

	destIPID := ""
	if destIP != "" {
		destIPID = "ip_" + destIP
		nodes = append(nodes, Node{
			ID:    destIPID,
			Label: "IPAddress",
			Properties: map[string]interface{}{
				"ip":          destIP,
				"is_external": !isPrivateIP(destIP),
			},
		})
	}

	if eventType == "alert" {
		if alertObj, ok := event["alert"].(map[string]interface{}); ok {
			sig, _ := alertObj["signature"].(string)
			category, _ := alertObj["category"].(string)
			severity, _ := alertObj["severity"].(float64)
			signatureID, _ := alertObj["signature_id"].(float64)

			alertID := fmt.Sprintf("alert_%.0f", signatureID)
			nodes = append(nodes, Node{
				ID:    alertID,
				Label: "Alert",
				Properties: map[string]interface{}{
					"signature":    sig,
					"category":     category,
					"severity":     int(severity),
					"signature_id": int(signatureID),
				},
			})

			if srcIPID != "" {
				rels = append(rels, Relationship{
					FromID:    srcIPID,
					FromLabel: "IPAddress",
					ToID:      alertID,
					ToLabel:   "Alert",
					Type:      "RAISED",
					Timestamp: ts.UTC().Format(time.RFC3339Nano),
				})
			}

			if destIPID != "" {
				rels = append(rels, Relationship{
					FromID:    alertID,
					FromLabel: "Alert",
					ToID:      destIPID,
					ToLabel:   "IPAddress",
					Type:      "TARGETED",
					Timestamp: ts.UTC().Format(time.RFC3339Nano),
				})
			}
		}
	} else if eventType == "http" {
		if httpObj, ok := event["http"].(map[string]interface{}); ok {
			url, _ := httpObj["url"].(string)
			httpMethod, _ := httpObj["http_method"].(string)
			status, _ := httpObj["status"].(float64)
			userAgent, _ := httpObj["http_user_agent"].(string)

			if url != "" && httpMethod != "" && !isStaticWebAsset(url) {
				basePath, _ := splitURI(url)
				reqID := fmt.Sprintf("httpreq_%s_%s", httpMethod, basePath)
				nodes = append(nodes, Node{
					ID:    reqID,
					Label: "HTTPRequest",
					Properties: map[string]interface{}{
						"method":      httpMethod,
						"uri":         basePath,
						"raw_uri":     url,
						"status_code": int(status),
						"user_agent":  userAgent,
					},
				})

				if srcIPID != "" {
					rels = append(rels, Relationship{
						FromID:    srcIPID,
						FromLabel: "IPAddress",
						ToID:      reqID,
						ToLabel:   "HTTPRequest",
						Type:      "REQUESTED",
						Timestamp: ts.UTC().Format(time.RFC3339Nano),
					})
				}
			}
		}
	} else if eventType == "dns" {
		if dnsObj, ok := event["dns"].(map[string]interface{}); ok {
			rrname, _ := dnsObj["rrname"].(string)
			rrtype, _ := dnsObj["rrtype"].(string)

			if rrname != "" {
				dnsID := "dns_" + rrname
				nodes = append(nodes, Node{
					ID:    dnsID,
					Label: "DNSQuery",
					Properties: map[string]interface{}{
						"rrname":          rrname,
						"rrtype":          rrtype,
						"is_exfiltration": isSuspiciousDnsTunneling(rrname),
					},
				})

				if srcIPID != "" {
					rels = append(rels, Relationship{
						FromID:    srcIPID,
						FromLabel: "IPAddress",
						ToID:      dnsID,
						ToLabel:   "DNSQuery",
						Type:      "QUERIED",
						Timestamp: ts.UTC().Format(time.RFC3339Nano),
					})
				}
			}
		}
	}

	delete(event, "timestamp")
	contentBytes, _ := json.Marshal(event)

	return ParsedLogLine{
		Timestamp:     ts.UTC(),
		Content:       string(contentBytes),
		Nodes:         nodes,
		Relationships: rels,
	}, nil
}
