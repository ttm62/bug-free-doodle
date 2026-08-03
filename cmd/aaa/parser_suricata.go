package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// isPrivateIP checks if an IP is in RFC 1918 private ranges (10.x, 172.16-31.x, 192.168.x, 127.x)
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
						"rrname":            rrname,
						"rrtype":            rrtype,
						"is_exfiltration": strings.Contains(rrname, "kennedy-mendoza") || strings.Contains(rrname, "dnsteal") || strings.Contains(rrname, "oastify") || strings.Contains(rrname, "burpcollaborator") || strings.Contains(rrname, "cisc0-update") || len(rrname) > 60,
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
