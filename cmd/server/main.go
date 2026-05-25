package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"log-api/internal/config"
	"log-api/internal/opensearch"
	"log-api/internal/routes"
)

func main() {
	cfg, err := config.LoadFromEnv()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Гарантируем, что индекс существует и на нём лежит нужный mapping.
	client := opensearch.NewClient(cfg)
	if err := client.EnsureIndex(context.Background()); err != nil {
		log.Fatalf("Failed to ensure index: %v", err)
	}

	router := routes.NewRouter(client)
	addr := cfg.ServerPort
	fmt.Printf("server started on %s\n", addr)
	log.Fatal(http.ListenAndServe(addr, router))
}
