package tsp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

type httpTimestamper struct {
	rt       http.RoundTripper
	url      string
	username string
	password string
}

func GetHttp(rt http.RoundTripper, url string, username string, password string) Timestamper {
	if rt == nil {
		rt = http.DefaultTransport
	}
	return &httpTimestamper{
		rt:       rt,
		url:      url,
		username: username,
		password: password,
	}
}

func (ts *httpTimestamper) Timestamp(ctx context.Context, req *Request) (*Response, error) {
	reqBytes, err := req.MarshalBinary()
	if err != nil {
		return nil, err
	}

	hReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ts.url, bytes.NewReader(reqBytes))
	if err != nil {
		return nil, err
	}
	hReq.Header.Set("Content-Type", "application/timestamp-query")

	if ts.username != "" && ts.password != "" {
		hReq.SetBasicAuth(ts.username, ts.password)
	}

	resp, err := ts.rt.RoundTrip(hReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}
	if contentType := resp.Header.Get("Content-Type"); contentType != "application/timestamp-reply" {
		return nil, fmt.Errorf("invalid response content type: %s", contentType)
	}

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	result := &Response{}
	if err := result.UnmarshalBinary(respBytes); err != nil {
		return nil, err
	}
	return result, nil
}
