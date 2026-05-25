package opensearch

import (
	"bytes"
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"log-api/internal/config"
	"log-api/internal/model"
)

//go:embed mapping.json
var mappingJSON []byte

type Client struct {
	httpClient *http.Client
	endpoint   string
	username   string
	password   string
	index      string
}

func NewClient(cfg *config.Config) *Client {
	return &Client{
		httpClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					// #nosec G402 -- self-signed cert в private network, принятый риск
					InsecureSkipVerify: true,
				},
			},
		},
		endpoint: cfg.OpensearchConfig.Address,
		username: cfg.OpensearchConfig.Username,
		password: cfg.OpensearchConfig.Password,
		index:    cfg.OpensearchConfig.Index,
	}
}

// EnsureIndex дожидается доступности OpenSearch, создаёт индекс если его нет
// и накатывает mapping.
func (c *Client) EnsureIndex(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, c.endpoint+"/"+c.index, nil)
	if err != nil {
		return fmt.Errorf("failed to create index check request: %w", err)
	}
	req.SetBasicAuth(c.username, c.password)

	for {
		resp, err := c.httpClient.Do(req)
		if err != nil {
			log.Println("error connecting to opensearch:", err)
			log.Println("retry in 5 sec...")
			time.Sleep(5 * time.Second)
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			break
		}
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("unauthorized, bad pass or user. Opensearch returns 401")
		}
		if resp.StatusCode == http.StatusNotFound {
			if err := c.createIndex(ctx); err != nil {
				return err
			}
			break
		}
		return fmt.Errorf("unexpected status_code when checking index: %d", resp.StatusCode)
	}

	return c.applyMapping(ctx)
}

func (c *Client) createIndex(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.endpoint+"/"+c.index, nil)
	if err != nil {
		return fmt.Errorf("failed to create index creation request: %w", err)
	}
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to create index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to create index, status_code: %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) applyMapping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.endpoint+"/"+c.index+"/_mapping", bytes.NewBuffer(mappingJSON))
	if err != nil {
		return fmt.Errorf("failed to create mapping request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to apply mapping: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		log.Printf("failed to apply mapping, status_code: %d. Ответ от серча: %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// IndexLog складывает один лог в индекс.
func (c *Client) IndexLog(ctx context.Context, entry model.LogEntry) error {
	body, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("failed to Marshal log: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/"+c.index+"/_doc", bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create Request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		log.Println("[ERROR] opensearch.IndexLog: unexpected status code", resp.StatusCode)
		log.Println("response.Body:", string(respBody))
		return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return nil
}

// searchResponse — минимальная обёртка ответа _search.
type searchResponse struct {
	Hits struct {
		Hits []struct {
			Source model.LogEntry `json:"_source"`
		} `json:"hits"`
	} `json:"hits"`
}

// SearchLogs возвращает все логи из индекса (до 1000 последних по времени).
func (c *Client) SearchLogs(ctx context.Context) ([]model.LogEntry, error) {
	query := `{"size":1000,"sort":[{"received_at":{"order":"desc"}}],"query":{"match_all":{}}}`

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint+"/"+c.index+"/_search", bytes.NewBufferString(query))
	if err != nil {
		return nil, fmt.Errorf("failed to create search request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send search request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(respBody))
	}

	var sr searchResponse
	if err := json.NewDecoder(resp.Body).Decode(&sr); err != nil {
		return nil, fmt.Errorf("failed to decode search response: %w", err)
	}

	logs := make([]model.LogEntry, 0, len(sr.Hits.Hits))
	for _, h := range sr.Hits.Hits {
		logs = append(logs, h.Source)
	}
	return logs, nil
}
