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
	version    = "0.0.2"
	apiBase    = "https://urlscan.io/api/v1"
	proApiBase = "https://pro.urlscan.io/api/v1"
)

type Client struct {
	apiKey     string
	httpClient httpClient
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

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

func HTTPClient(client httpClient) Option {
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
	_, err := c.do(ctx, http.MethodGet, apiBase+"/search?"+params.Encode(), nil, &resp)
	if err != nil {
		return SearchResponse{}, err
	}
	return resp, nil
}

func (c *Client) Scan(ctx context.Context, request ScanRequest) (ScanResponse, error) {
	var resp ScanResponse
	_, err := c.do(ctx, http.MethodPost, apiBase+"/scan", request, &resp)
	if err != nil {
		return ScanResponse{}, err
	}
	return resp, nil
}

func (c Client) ListLiveScanners(ctx context.Context) (LiveScannersResponse, error) {
	resp := LiveScannersResponse{}
	_, err := c.do(ctx, http.MethodGet, proApiBase+"/livescan/scanners/", nil, &resp)
	return resp, err
}

func (c Client) LiveScan(ctx context.Context, request ScanRequest) (LiveScanResult, error) {
	resp := livescanResponse{}
	_, err := c.do(ctx, http.MethodPost, fmt.Sprintf("%s/livescan/%s/scan/", proApiBase, request.Country),
		liveScanRequest{
			Scanner: liveScanParams{
				UserAgent: request.UserAgent,
			},
			Task: liveScanTask{
				Url:  request.URL,
				Tags: request.Tags,
			},
		}, &resp)
	if err != nil {
		return LiveScanResult{}, err
	}

	scanResult := LiveScanResult{}
	_, err = c.do(ctx, http.MethodGet, fmt.Sprintf("%s/livescan/%s/obj/%s", proApiBase, request.Country, resp.UUID), nil, &scanResult)
	return scanResult, err
}

func (c Client) PersistLiveScan(ctx context.Context, liveScanner string, scanRequest PersistLiveScanRequest) error {
	_, err := c.do(ctx, http.MethodPut, fmt.Sprintf("%s/livescan/%s/%s/", proApiBase, liveScanner, scanRequest.UUID), persistLiveScanRequest{Task: scanRequest}, &struct{}{})
	return err
}

func (c *Client) PollResult(ctx context.Context, uuid string) (ScanResult, error) {
	// Poll every two seconds for up to a minute
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()

	var lastErr error
	for {
		result, err := c.RetrieveResult(ctx, uuid)
		if err == nil {
			return result, nil
		}
		if errors.As(err, &Error{}) {
			lastErr = err
		}

		select {
		case <-ctx.Done():
			return ScanResult{}, errors.Join(lastErr, ctx.Err())
		case <-t.C:
			continue
		}
	}
}

func (c Client) RetrieveResult(ctx context.Context, uuid string) (ScanResult, error) {
	result := ScanResult{}
	_, err := c.do(ctx, http.MethodGet, apiBase+"/result/"+uuid, nil, &result)
	return result, err
}

func (c *Client) do(ctx context.Context, method, url string, request, response any) (*http.Response, error) {
	// create request
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "phish.report/urlscanio-go v"+version)
	if request != nil {
		requestBody, err := json.Marshal(request)
		if err != nil {
			return nil, err
		}
		fmt.Println(url, "sending payload", string(requestBody))
		req.Body = io.NopCloser(bytes.NewReader(requestBody))
		req.Header.Set("Content-Type", "application/json")
	}
	if c.apiKey != "" {
		req.Header.Set("API-Key", c.apiKey)
	}

	// create client
	var client httpClient = http.DefaultClient
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
		return resp, Error{
			Message:     "internal",
			Description: err.Error(),
			Status:      http.StatusInternalServerError,
		}
	}
	if e.Status == 0 {
		return resp, nil
	}
	return resp, e
}
