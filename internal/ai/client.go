package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

type Client struct {
	BaseURL string
	Model   string
	http    *http.Client
}

func New(baseURL, model string, timeout time.Duration) *Client {
	return &Client{
		BaseURL: baseURL,
		Model:   model,
		http:    &http.Client{Timeout: timeout},
	}
}

func (c *Client) EnsureModel(ctx context.Context) error {
	body, _ := json.Marshal(map[string]any{"name": c.Model, "stream": false})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/pull", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	slog.Info("ensuring model is available (first run may take several minutes)", "model", c.Model)
	puller := &http.Client{Timeout: 30 * time.Minute}
	resp, err := puller.Do(req)
	if err != nil {
		return fmt.Errorf("pull model: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("pull model returned %s", resp.Status)
	}
	slog.Info("model ready", "model", c.Model)
	return nil
}

type generateRequest struct {
	Model   string         `json:"model"`
	Prompt  string         `json:"prompt"`
	System  string         `json:"system"`
	Stream  bool           `json:"stream"`
	Format  string         `json:"format"`
	Options map[string]any `json:"options"`
}

type generateResponse struct {
	Response string `json:"response"`
	Done     bool   `json:"done"`
}

func (c *Client) GenerateJSON(ctx context.Context, system, prompt string) (string, error) {
	body, _ := json.Marshal(generateRequest{
		Model:  c.Model,
		Prompt: prompt,
		System: system,
		Stream: false,
		Format: "json",
		Options: map[string]any{
			"temperature": 0,
			"num_ctx":     4096,
			"num_predict": 600,
		},
	})

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/api/generate", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("ollama returned %s", resp.Status)
	}

	var out generateResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("decode ollama response: %w", err)
	}
	return out.Response, nil
}

func (c *Client) Ping(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/api/tags", nil)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("ollama unhealthy: %s", resp.Status)
	}
	return nil
}
