package urlscanio

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const (
	version = "0.0.1"
	apiBase = "https://urlscan.io/api/v1"
)

type Client struct {
	apiKey     string
	httpClient *http.Client
}

type Option func(*Client)

func NewClient(options ...Option) *Client {
	c := &Client{}

	for _, option := range options {
		option(c)
	}
	return c
}

func APIKey(key string) Option {
	return func(client *Client) {
		client.apiKey = key
	}
}

func HTTPClient(client *http.Client) Option {
	return func(c *Client) {
		c.httpClient = client
	}
}

func (c *Client) Search(ctx context.Context, request SearchRequest) (SearchResponse, error) {
	params := url.Values{}
	params.Set("q", request.Query)
	if request.Size != 0 {
		params.Set("size", fmt.Sprint(request.Size))
	}
	if request.SearchAfter != "" {
		params.Set("search_after", request.SearchAfter)
	}

	var resp SearchResponse
	_, err := c.do(ctx, http.MethodGet, "/search?"+params.Encode(), nil, &resp)
	if err != nil {
		return SearchResponse{}, err
	}
	return resp, nil
}

func (c *Client) Scan(ctx context.Context, request ScanRequest) (ScanResponse, error) {
	var resp ScanResponse
	_, err := c.do(ctx, http.MethodPost, "/scan", request, &resp)
	if err != nil {
		return ScanResponse{}, err
	}
	return resp, nil
}

func (c *Client) PollResult(ctx context.Context, uuid string) (ScanResult, error) {
	// Poll every two seconds for up to a minute
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	var result ScanResult
	var err error
	for {
		result, err = c.RetrieveResult(ctx, uuid)
		if err == nil {
			return result, nil
		}

		select {
		case <-ctx.Done():
			return ScanResult{}, errors.Join(ctx.Err(), err)
		case <-t.C:
			continue
		}
	}
}

func (c Client) RetrieveResult(ctx context.Context, uuid string) (ScanResult, error) {
	result := ScanResult{}
	_, err := c.do(ctx, http.MethodGet, "/result/"+uuid, nil, &result)
	return result, err
}

func (c *Client) do(ctx context.Context, method, path string, request, response any) (*http.Response, error) {
	// create request
	req, err := http.NewRequestWithContext(ctx, method, apiBase+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "phish.report/urlscanio-go v"+version)
	if request != nil {
		requestBody, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(requestBody))
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("API-Key", c.apiKey)
	}

	// create client
	client := http.DefaultClient
	if c.httpClient != nil {
		client = c.httpClient
	}

	// TODO: handle rate limit headers from response
	resp, err := client.Do(req)
	if err != nil {
		return resp, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, err
	}

	var e Error
	if resp.StatusCode/100 == 2 {
		err = json.Unmarshal(body, response)
	} else {
		_ = json.Unmarshal(body, &e) // in many instances the body is empty so ignore this unmarshalling error
		if e.Status == 0 {
			e.Status = resp.StatusCode
			e.Message = resp.Status
		}
	}
	if err != nil {
		return resp, err
	}
	if e.Status == 0 {
		return resp, nil
	}
	return resp, e
}
