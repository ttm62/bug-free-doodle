package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"

	. "hook/pkg/utils"
)

type WazuhMessage struct {
	Timestamp string `json:"timestamp"`
	FullLog   string `json:"full_log"`
}

type VectorEvent struct {
	File       string       `json:"file"`
	Host       string       `json:"host"`
	Message    WazuhMessage `json:"message"`
	SourceType string       `json:"source_type"`
	Timestamp  string       `json:"timestamp"`
}

func rawLogHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var events []VectorEvent
	if err := json.Unmarshal(body, &events); err != nil {
		log.Printf("[Lỗi Parse JSON ngoài]: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	for _, e := range events {
		Println(WhiteColor, Pretty(e))
	}

	w.WriteHeader(http.StatusOK)
}

func main() {
	http.HandleFunc("/raw_logs", rawLogHandler)
	log.Println("[*] Golang Webhook đang lắng nghe raw log buffer tại cổng 5050...")
	http.ListenAndServe(":5050", nil)
}
