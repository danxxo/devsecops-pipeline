package handler

import "log-api/internal/opensearch"

type LogHandler struct {
	client *opensearch.Client
}

func NewLogHandler(client *opensearch.Client) *LogHandler {
	return &LogHandler{client: client}
}
