package handler

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"time"

	"log-api/internal/model"
	"log-api/internal/pkg"
)

// HandleLog принимает JSON-лог, обогащает его IP клиента и временем приёма
// и индексирует в OpenSearch.
func (h *LogHandler) HandleLog(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		log.Println("[ERROR] HandleLog: Failed to read request body", err)
		return
	}
	defer r.Body.Close()

	var entry model.LogEntry
	if err := json.Unmarshal(body, &entry); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		log.Println("[ERROR] HandleLog: Invalid JSON", err)
		return
	}

	entry.ClientIP = pkg.GetClientIP(r)
	entry.ReceivedAt = time.Now().UTC().Format(time.RFC3339)

	if err := h.client.IndexLog(r.Context(), entry); err != nil {
		http.Error(w, "Failed to index log", http.StatusInternalServerError)
		log.Println("[ERROR] HandleLog: Failed to index log", err)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// ListLogs возвращает все логи из OpenSearch.
func (h *LogHandler) ListLogs(w http.ResponseWriter, r *http.Request) {
	logs, err := h.client.SearchLogs(r.Context())
	if err != nil {
		http.Error(w, "Failed to fetch logs", http.StatusInternalServerError)
		log.Println("[ERROR] ListLogs: Failed to fetch logs", err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if err := json.NewEncoder(w).Encode(logs); err != nil {
		log.Println("[ERROR] ListLogs: Failed to encode response", err)
	}
}
