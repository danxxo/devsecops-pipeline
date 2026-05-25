package model

// LogEntry — единая модель лога. Поля timestamp/level/service/message/details
// приходят от клиента в POST /log; client_ip и received_at проставляет сам сервис
// перед индексацией. Эта же структура возвращается из GET /log.
type LogEntry struct {
	Timestamp  string                 `json:"timestamp,omitempty"`
	Level      string                 `json:"level"`
	Service    string                 `json:"service"`
	Message    string                 `json:"message"`
	Details    map[string]interface{} `json:"details,omitempty"`
	ClientIP   string                 `json:"client_ip,omitempty"`
	ReceivedAt string                 `json:"received_at,omitempty"`
}
