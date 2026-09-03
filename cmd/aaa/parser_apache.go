package main

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// isStaticWebAsset kiểm tra URI có phải assets.
// Ví dụ: /style.css, /bundle.js, /favicon.ico, /logo.png?v=1.
func isStaticWebAsset(uri string) bool {
	cleanURI := strings.ToLower(uri)
	if idx := strings.IndexByte(cleanURI, '?'); idx > 0 {
		cleanURI = cleanURI[:idx]
	}
	return strings.HasSuffix(cleanURI, ".css") ||
		strings.HasSuffix(cleanURI, ".js") ||
		strings.HasSuffix(cleanURI, ".jpg") ||
		strings.HasSuffix(cleanURI, ".jpeg") ||
		strings.HasSuffix(cleanURI, ".png") ||
		strings.HasSuffix(cleanURI, ".gif") ||
		strings.HasSuffix(cleanURI, ".ico") ||
		strings.HasSuffix(cleanURI, ".woff") ||
		strings.HasSuffix(cleanURI, ".woff2") ||
		strings.HasSuffix(cleanURI, ".ttf") ||
		strings.HasSuffix(cleanURI, ".svg") ||
		strings.HasSuffix(cleanURI, ".map") ||
		strings.HasSuffix(cleanURI, "robots.txt")
}

// splitURI tách base path và query string, giới hạn độ dài tối đa 100 ký tự.
// Ví dụ: /api/login?user=admin -> /api/login, user=admin.
func splitURI(uri string) (string, string) {
	base := uri
	query := ""
	if idx := strings.IndexByte(uri, '?'); idx > 0 {
		base = uri[:idx]
		query = uri[idx+1:]
	}
	if len(base) > 100 {
		base = base[:100]
	}
	return base, query
}

// parseApacheAccessLogLine phân tích log thành các Node IPAddress, HTTPRequest và quan hệ REQUESTED.
// Ví dụ log: 192.168.1.10 - - [24/Jan/2022:14:39:57 +0000] "POST /wp-login.php HTTP/1.1" 200 5320 "-" "WPScan v3.8"
func parseApacheAccessLogLine(input string) (ParsedLogLine, error) {
	openBracket := strings.IndexByte(input, '[')
	closeBracket := strings.IndexByte(input[openBracket+1:], ']')
	if openBracket < 0 || closeBracket < 0 {
		return ParsedLogLine{}, fmt.Errorf("apache access line has no timestamp bracket")
	}
	closeBracket += openBracket + 1

	timestampText := input[openBracket+1 : closeBracket]
	ts, err := time.Parse("02/Jan/2006:15:04:05 -0700", timestampText)
	if err != nil {
		return ParsedLogLine{}, fmt.Errorf("failed to parse apache timestamp: %w", err)
	}

	clientIP := strings.TrimSpace(input[:openBracket])
	if idx := strings.IndexByte(clientIP, ' '); idx > 0 {
		clientIP = clientIP[:idx]
	}

	suffix := ""
	if closeBracket+1 < len(input) {
		suffix = strings.TrimLeft(input[closeBracket+1:], " ")
	}

	method := ""
	uri := ""
	statusCode := 0
	userAgent := ""

	if strings.HasPrefix(suffix, `"`) {
		firstQuoteEnd := strings.Index(suffix[1:], `"`)
		if firstQuoteEnd > 0 {
			reqLine := suffix[1 : firstQuoteEnd+1]
			reqParts := strings.Fields(reqLine)
			if len(reqParts) >= 2 {
				method = reqParts[0]
				uri = reqParts[1]
			}

			rest := strings.TrimSpace(suffix[firstQuoteEnd+2:])
			// In Apache Combined Log format, rest has: STATUS SIZE "REFERER" "USER_AGENT"
			restParts := strings.Fields(rest)
			if len(restParts) >= 1 {
				statusCode, _ = strconv.Atoi(restParts[0])
			}

			// Extract User-Agent from last quoted string
			if lastQuoteStart := strings.LastIndex(suffix, `"`); lastQuoteStart > firstQuoteEnd+1 {
				prevQuoteStart := strings.LastIndex(suffix[:lastQuoteStart], `"`)
				if prevQuoteStart > firstQuoteEnd {
					userAgent = suffix[prevQuoteStart+1 : lastQuoteStart]
				}
			}
		}
	}

	// Filter out static web assets
	if uri != "" && isStaticWebAsset(uri) {
		return ParsedLogLine{Timestamp: ts.UTC(), Content: clientIP + " " + suffix}, nil
	}

	var nodes []Node
	var rels []Relationship

	ipID := "ip_" + clientIP
	nodes = append(nodes, Node{
		ID:    ipID,
		Label: "IPAddress",
		Properties: map[string]interface{}{
			"ip": clientIP,
		},
	})

	if uri != "" && method != "" {
		basePath, queryParams := splitURI(uri)
		reqID := fmt.Sprintf("httpreq_%s_%s", method, basePath)

		uaLower := strings.ToLower(userAgent)
		uriLower := strings.ToLower(uri)

		isScanner := strings.Contains(uaLower, "nmap") ||
			strings.Contains(uaLower, "wpscan") ||
			strings.Contains(uaLower, "dirb") ||
			strings.Contains(uaLower, "nikto") ||
			strings.Contains(uaLower, "sqlmap") ||
			strings.Contains(uaLower, "python-requests") ||
			strings.Contains(uaLower, "curl")

		isSuspiciousPayload := strings.Contains(uriLower, "cmd=") ||
			strings.Contains(uriLower, "exec=") ||
			strings.Contains(uriLower, "whoami") ||
			strings.Contains(uriLower, "id=") ||
			strings.Contains(uriLower, "passwd") ||
			strings.Contains(uriLower, "shadow") ||
			strings.Contains(uriLower, "eval(") ||
			strings.Contains(uriLower, "base64") ||
			strings.Contains(uriLower, "wordlist") ||
			strings.Contains(uriLower, "<script") ||
			strings.Contains(uriLower, "union") ||
			strings.Contains(uriLower, "select") ||
			strings.Contains(uriLower, "or 1=1") ||
			strings.Contains(uriLower, "' or '") ||
			strings.Contains(uriLower, "../")

		nodes = append(nodes, Node{
			ID:    reqID,
			Label: "HTTPRequest",
			Properties: map[string]interface{}{
				"method":                method,
				"uri":                   basePath,
				"query_params":          queryParams,
				"raw_uri":               uri,
				"status_code":           statusCode,
				"user_agent":            userAgent,
				"is_scanner":            isScanner,
				"is_suspicious_payload": isSuspiciousPayload,
			},
		})

		rels = append(rels, Relationship{
			FromID:    ipID,
			FromLabel: "IPAddress",
			ToID:      reqID,
			ToLabel:   "HTTPRequest",
			Type:      "REQUESTED",
			Timestamp: ts.UTC().Format(time.RFC3339Nano),
		})
	}

	content := clientIP + " " + suffix
	return ParsedLogLine{
		Timestamp:     ts.UTC(),
		Content:       content,
		Nodes:         nodes,
		Relationships: rels,
	}, nil
}
