package routes

import (
	"log-api/internal/handler"
	"log-api/internal/middleware"
	"log-api/internal/opensearch"

	"github.com/gorilla/mux"
)

func NewRouter(client *opensearch.Client) *mux.Router {
	router := mux.NewRouter()
	router.Use(middleware.SecurityHeaders)

	logHandler := handler.NewLogHandler(client)

	router.HandleFunc("/log", logHandler.HandleLog).Methods("POST")
	router.HandleFunc("/log", logHandler.ListLogs).Methods("GET")
	router.HandleFunc("/_ping", logHandler.Ping).Methods("GET")
	router.HandleFunc("/vuln", logHandler.Vuln).Methods("GET") // намеренная уязвимость для DAST-гейта

	return router
}
