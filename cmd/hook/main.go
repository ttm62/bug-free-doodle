package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type WazuhMessage struct {
	FullLog string `json:"full_log"`
}

type VectorEvent struct {
	Message WazuhMessage `json:"message"`
}

func handleRawLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Vector gửi theo batch dạng mảng các event [...]
	var events []VectorEvent
	if err := json.Unmarshal(body, &events); err == nil {
		for _, e := range events {
			if e.Message.FullLog != "" {
				fmt.Printf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), e.Message.FullLog)
			}
		}
	} else {
		// Trường hợp Vector gửi 1 event đơn lẻ {...}
		var singleEvent VectorEvent
		if err := json.Unmarshal(body, &singleEvent); err == nil {
			if singleEvent.Message.FullLog != "" {
				fmt.Printf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), singleEvent.Message.FullLog)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok"}`))
}

func main() {
	http.HandleFunc("/raw_logs", handleRawLogs)

	port := ":5050"
	log.Printf("🚀 Webhook server is listening on http://0.0.0.0%s/raw_logs ...\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
