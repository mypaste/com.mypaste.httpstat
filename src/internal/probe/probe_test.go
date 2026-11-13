package probe

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "bare host becomes https", input: "example.com/a?b=1", want: "https://example.com/a?b=1"},
		{name: "keeps http", input: " http://example.com/ ", want: "http://example.com/"},
		{name: "keeps https", input: "https://example.com/x", want: "https://example.com/x"},
		{name: "empty", input: "   ", wantErr: true},
		{name: "multi line", input: "https://example.com/\nmore", wantErr: true},
		{name: "unsupported scheme", input: "ftp://example.com/file", wantErr: true},
		{name: "missing host", input: "https:///path", wantErr: true},
		{name: "too long", input: "https://example.com/" + strings.Repeat("a", maxURLLength), wantErr: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := Normalize(testCase.input)
			if testCase.wantErr {
				if err == nil {
					t.Fatalf("Normalize(%q) = %q, want error", testCase.input, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("Normalize(%q) failed: %v", testCase.input, err)
			}
			if got != testCase.want {
				t.Fatalf("Normalize(%q) = %q, want %q", testCase.input, got, testCase.want)
			}
		})
	}
}

func TestProbeMeasuresOneResponse(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if got := request.Header.Get("User-Agent"); got != userAgent {
			t.Errorf("User-Agent = %q, want %q", got, userAgent)
		}
		writer.Header().Set("X-Test", "one")
		writer.Header().Add("X-Test", "two")
		writer.Header().Set("Content-Type", "text/plain")
		writer.WriteHeader(http.StatusOK)
		time.Sleep(30 * time.Millisecond)
		_, _ = writer.Write([]byte("hello world"))
	}))
	defer server.Close()

	report, err := Probe(context.Background(), server.URL+"/path", Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("server saw %d requests, want 1", requests.Load())
	}
	if report.Status != 200 || report.StatusText != "OK" {
		t.Fatalf("status = %d %q", report.Status, report.StatusText)
	}
	if report.StatusLine != "HTTP/1.1 200 OK" {
		t.Fatalf("status line = %q", report.StatusLine)
	}
	if report.Proto != "HTTP/1.1" {
		t.Fatalf("proto = %q", report.Proto)
	}
	if report.Size != int64(len("hello world")) {
		t.Fatalf("size = %d, want %d", report.Size, len("hello world"))
	}
	if report.BodyTruncated {
		t.Fatal("body reported truncated")
	}
	if report.ContentType != "text/plain" {
		t.Fatalf("content type = %q", report.ContentType)
	}
	if report.RemoteIP != "127.0.0.1" || report.RemotePort == "" {
		t.Fatalf("remote = %q / %q", report.RemoteIP, report.RemotePort)
	}
	if report.TLS != nil {
		t.Fatal("plain HTTP reported TLS details")
	}
	headers := map[string][]string{}
	for _, header := range report.Headers {
		headers[header.Name] = append(headers[header.Name], header.Value)
	}
	if got := strings.Join(headers["X-Test"], ","); got != "one,two" {
		t.Fatalf("X-Test headers = %q", got)
	}

	timings := report.Timings
	if timings.DNS != 0 {
		t.Fatalf("DNS = %v for an IP literal, want 0", timings.DNS)
	}
	if timings.Server < 20 {
		t.Fatalf("server processing = %v ms, want at least 20", timings.Server)
	}
	if timings.Total < timings.Server {
		t.Fatalf("total %v < server %v", timings.Total, timings.Server)
	}
	if timings.StartTransfer > timings.Total+0.1 {
		t.Fatalf("starttransfer %v > total %v", timings.StartTransfer, timings.Total)
	}
	if timings.PreTransfer > timings.StartTransfer+0.1 {
		t.Fatalf("pretransfer %v > starttransfer %v", timings.PreTransfer, timings.StartTransfer)
	}
	if timings.NameLookup > timings.PreTransfer+0.1 {
		t.Fatalf("namelookup %v > pretransfer %v", timings.NameLookup, timings.PreTransfer)
	}
}

func TestProbeReportsTLSHandshake(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte("secure"))
	}))
	defer server.Close()

	report, err := Probe(context.Background(), server.URL, Options{
		Timeout:   5 * time.Second,
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, // the test server's certificate is self-signed
	})
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if report.TLS == nil {
		t.Fatal("HTTPS reported no TLS details")
	}
	if !strings.HasPrefix(report.TLS.Version, "TLS ") {
		t.Fatalf("TLS version = %q", report.TLS.Version)
	}
	if report.TLS.Cipher == "" {
		t.Fatal("TLS cipher is empty")
	}
	if report.Timings.TLS <= 0 {
		t.Fatalf("TLS timing = %v", report.Timings.TLS)
	}
}

func TestProbeReportsAnHTTPErrorAsAResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		http.Error(writer, "gone", http.StatusNotFound)
	}))
	defer server.Close()

	report, err := Probe(context.Background(), server.URL, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if report.Status != 404 || report.StatusText != "Not Found" {
		t.Fatalf("status = %d %q", report.Status, report.StatusText)
	}
	if report.Size != int64(len("gone\n")) {
		t.Fatalf("size = %d, want %d", report.Size, len("gone\n"))
	}
}

func TestProbeKeepsAnUnregisteredStatusText(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(599)
	}))
	defer server.Close()

	report, err := Probe(context.Background(), server.URL, Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if report.Status != 599 || report.StatusText != "status code 599" {
		t.Fatalf("status = %d %q, want 599 with the status line's own words", report.Status, report.StatusText)
	}
}

func TestProbeDoesNotFollowRedirects(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		if request.URL.Path == "/next" {
			t.Error("redirect was followed")
			_, _ = writer.Write([]byte("next"))
			return
		}
		writer.Header().Set("Location", "/next")
		writer.WriteHeader(http.StatusFound)
	}))
	defer server.Close()

	report, err := Probe(context.Background(), server.URL+"/start", Options{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if requests.Load() != 1 {
		t.Fatalf("server saw %d requests, want 1", requests.Load())
	}
	if report.Status != http.StatusFound {
		t.Fatalf("status = %d, want 302", report.Status)
	}
	found := false
	for _, header := range report.Headers {
		if header.Name == "Location" && header.Value == "/next" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Location header missing from %+v", report.Headers)
	}
}

func TestProbeTruncatesALargeBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write([]byte(strings.Repeat("x", 4096)))
	}))
	defer server.Close()

	report, err := Probe(context.Background(), server.URL, Options{
		Timeout:  5 * time.Second,
		MaxBytes: 1024,
	})
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if report.Size != 1024 {
		t.Fatalf("size = %d, want 1024", report.Size)
	}
	if !report.BodyTruncated {
		t.Fatal("body was not reported truncated")
	}
}

func TestProbeDescribesATimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		time.Sleep(500 * time.Millisecond)
		_, _ = writer.Write([]byte("late"))
	}))
	defer server.Close()

	_, err := Probe(context.Background(), server.URL, Options{Timeout: 100 * time.Millisecond})
	if err == nil {
		t.Fatal("Probe succeeded past its timeout")
	}
	if !strings.Contains(err.Error(), "超时") {
		t.Fatalf("error = %q, want a timeout message", err)
	}
}

func TestProbeDescribesARejectedConnection(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()

	_, probeErr := Probe(context.Background(), "http://"+address+"/", Options{Timeout: 2 * time.Second})
	if probeErr == nil {
		t.Fatal("Probe succeeded against a closed port")
	}
	if !strings.Contains(probeErr.Error(), "拒绝") {
		t.Fatalf("error = %q, want a refused-connection message", probeErr)
	}
}

func TestReportMarshalsThePageContract(t *testing.T) {
	report := Report{
		URL:        "https://example.com/",
		Method:     "GET",
		Status:     200,
		StatusText: "OK",
		StatusLine: "HTTP/2.0 200 OK",
		Proto:      "HTTP/2.0",
		Headers:    []Header{{Name: "Content-Type", Value: "text/html"}},
		Timings:    Timings{Total: 12.3},
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatalf("marshal failed: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	for _, name := range []string{
		"url", "method", "status", "statusText", "statusLine", "proto",
		"contentLength", "size", "bodyTruncated", "headers", "timings",
	} {
		if _, ok := fields[name]; !ok {
			t.Fatalf("report JSON is missing %q: %s", name, encoded)
		}
	}
	timings, ok := fields["timings"].(map[string]any)
	if !ok {
		t.Fatalf("timings is not an object: %s", encoded)
	}
	for _, name := range []string{
		"dns", "connect", "tls", "server", "transfer", "total",
		"namelookup", "pretransfer", "starttransfer",
	} {
		if _, ok := timings[name]; !ok {
			t.Fatalf("timings is missing %q: %s", name, encoded)
		}
	}
}
