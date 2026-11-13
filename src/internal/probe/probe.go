// Package probe measures one HTTP request the way httpstat does: a single GET
// is traced with net/http/httptrace and split into DNS lookup, TCP connection,
// TLS handshake, server processing and content transfer. Nothing here follows
// a redirect or retries: the report describes exactly the response the origin
// returned, so the timings stay attached to one connection.
package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	// DefaultTimeout stays below the host's ten-second surface invocation
	// budget (PLUGINS.md §4.1), leaving room to answer with an error.
	DefaultTimeout = 8 * time.Second
	// DefaultMaxBytes bounds how much body is drained. A larger body only
	// affects the transfer duration; the report says it was truncated.
	DefaultMaxBytes = 8 << 20
	userAgent       = "MyPaste-HTTPStat/1.0"
	maxURLLength    = 4096
	maxHeaderValue  = 512
	maxHeaderCount  = 64
)

// Options are the caller's bounds. A zero value means the default.
type Options struct {
	Timeout   time.Duration
	MaxBytes  int64
	TLSConfig *tls.Config // tests only: nothing in the package sets it
}

// Timings are milliseconds relative to the first byte sent. Phase values are
// durations; NameLookup, PreTransfer and StartTransfer are cumulative marks,
// matching curl's time_namelookup / time_pretransfer / time_starttransfer.
type Timings struct {
	DNS           float64 `json:"dns"`
	Connect       float64 `json:"connect"`
	TLS           float64 `json:"tls"`
	Server        float64 `json:"server"`
	Transfer      float64 `json:"transfer"`
	Total         float64 `json:"total"`
	NameLookup    float64 `json:"namelookup"`
	PreTransfer   float64 `json:"pretransfer"`
	StartTransfer float64 `json:"starttransfer"`
}

// TLSInfo is what the handshake negotiated. It is absent for plain HTTP.
type TLSInfo struct {
	Version    string `json:"version"`
	Cipher     string `json:"cipher"`
	ServerName string `json:"serverName,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

// Header is one response header field. Repeated fields stay separate.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Report is the complete answer the page renders.
type Report struct {
	URL           string   `json:"url"`
	Method        string   `json:"method"`
	Status        int      `json:"status"`
	StatusText    string   `json:"statusText"`
	StatusLine    string   `json:"statusLine"`
	Proto         string   `json:"proto"`
	RemoteAddr    string   `json:"remoteAddr,omitempty"`
	RemoteIP      string   `json:"remoteIp,omitempty"`
	RemotePort    string   `json:"remotePort,omitempty"`
	TLS           *TLSInfo `json:"tls,omitempty"`
	ContentType   string   `json:"contentType,omitempty"`
	ContentLength int64    `json:"contentLength"`
	Size          int64    `json:"size"`
	BodyTruncated bool     `json:"bodyTruncated"`
	Headers       []Header `json:"headers"`
	Timings       Timings  `json:"timings"`
}

// Normalize turns what the user typed into a request URL. A bare host gets
// https:// (the modern default); only http and https are accepted, so this
// command cannot be aimed at file:, data: or another scheme.
func Normalize(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", errors.New("链接为空")
	}
	if len(value) > maxURLLength {
		return "", fmt.Errorf("链接超过 %d 个字符", maxURLLength)
	}
	if strings.ContainsAny(value, "\r\n\t ") {
		return "", errors.New("链接只能是一行，不能包含空白")
	}
	if !strings.Contains(value, "://") {
		value = "https://" + value
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return "", errors.New("无法解析这条链接")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
	case "":
		return "", errors.New("链接缺少 http 或 https")
	default:
		return "", fmt.Errorf("只能计时 http 或 https 链接（当前是 %s）", parsed.Scheme)
	}
	if parsed.Host == "" {
		return "", errors.New("链接缺少主机名")
	}
	return parsed.String(), nil
}

// trace collects the httptrace callbacks. The transport may call them from
// more than one goroutine, so every field is read and written under mu.
type trace struct {
	mu          sync.Mutex
	dnsStart    time.Time
	dnsDone     time.Time
	connectFrom time.Time
	connectDone time.Time
	tlsStart    time.Time
	tlsDone     time.Time
	wrote       time.Time
	firstByte   time.Time
	remoteAddr  string
	tlsState    *tls.ConnectionState
}

// Probe performs one GET and returns its report. Transport failures come back
// as errors in the page's own wording; an HTTP error status is a report, not
// an error.
func Probe(ctx context.Context, raw string, options Options) (Report, error) {
	target, err := Normalize(raw)
	if err != nil {
		return Report{}, err
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	limit := options.MaxBytes
	if limit <= 0 {
		limit = DefaultMaxBytes
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var recorded trace
	clientTrace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) {
			recorded.mu.Lock()
			if recorded.dnsStart.IsZero() {
				recorded.dnsStart = time.Now()
			}
			recorded.mu.Unlock()
		},
		DNSDone: func(httptrace.DNSDoneInfo) {
			recorded.mu.Lock()
			recorded.dnsDone = time.Now()
			recorded.mu.Unlock()
		},
		ConnectStart: func(_, _ string) {
			recorded.mu.Lock()
			if recorded.connectFrom.IsZero() {
				recorded.connectFrom = time.Now()
			}
			recorded.mu.Unlock()
		},
		ConnectDone: func(_, _ string, err error) {
			if err != nil {
				return
			}
			recorded.mu.Lock()
			recorded.connectDone = time.Now()
			recorded.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			recorded.mu.Lock()
			recorded.tlsStart = time.Now()
			recorded.mu.Unlock()
		},
		TLSHandshakeDone: func(state tls.ConnectionState, err error) {
			if err != nil {
				return
			}
			recorded.mu.Lock()
			recorded.tlsDone = time.Now()
			copied := state
			recorded.tlsState = &copied
			recorded.mu.Unlock()
		},
		GotConn: func(info httptrace.GotConnInfo) {
			recorded.mu.Lock()
			if info.Conn != nil {
				recorded.remoteAddr = info.Conn.RemoteAddr().String()
			}
			recorded.mu.Unlock()
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			if info.Err != nil {
				return
			}
			recorded.mu.Lock()
			recorded.wrote = time.Now()
			recorded.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			recorded.mu.Lock()
			recorded.firstByte = time.Now()
			recorded.mu.Unlock()
		},
	}

	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   5 * time.Second,
		ForceAttemptHTTP2:     true,
		DisableKeepAlives:     true,
		DisableCompression:    true,
		MaxIdleConns:          1,
		ResponseHeaderTimeout: 0,
		TLSClientConfig:       options.TLSConfig,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		// httpstat measures the response the origin sent; a redirect is
		// reported with its status and Location, never followed.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	request, err := http.NewRequestWithContext(
		httptrace.WithClientTrace(ctx, clientTrace), http.MethodGet, target, nil)
	if err != nil {
		return Report{}, errors.New("无法创建这次请求")
	}
	request.Header.Set("User-Agent", userAgent)
	request.Header.Set("Accept", "*/*")

	start := time.Now()
	response, err := client.Do(request)
	if err != nil {
		return Report{}, describe(err, timeout)
	}
	defer response.Body.Close()

	size, truncated, err := drain(response.Body, limit)
	if err != nil {
		return Report{}, describe(err, timeout)
	}
	end := time.Now()

	report := Report{
		URL:           target,
		Method:        http.MethodGet,
		Status:        response.StatusCode,
		StatusText:    http.StatusText(response.StatusCode),
		StatusLine:    strings.TrimSpace(response.Proto + " " + response.Status),
		Proto:         response.Proto,
		ContentType:   response.Header.Get("Content-Type"),
		ContentLength: response.ContentLength,
		Size:          size,
		BodyTruncated: truncated,
		Headers:       responseHeaders(response.Header),
		Timings:       recorded.timings(start, end),
	}
	report.Headers = report.Headers[:min(len(report.Headers), maxHeaderCount)]
	// http.StatusText only knows the registered codes; an origin may answer
	// with another one, and the status line still says what it means.
	if report.StatusText == "" {
		report.StatusText = strings.TrimSpace(strings.TrimPrefix(response.Status, strconv.Itoa(response.StatusCode)))
	}
	if info := recorded.tlsInfo(); info != nil {
		report.TLS = info
	}
	report.RemoteAddr = recorded.remote()
	if report.RemoteAddr != "" {
		if host, port, splitErr := net.SplitHostPort(report.RemoteAddr); splitErr == nil {
			report.RemoteIP = host
			report.RemotePort = port
		}
	}
	return report, nil
}

// tlsInfo and remote copy the trace's last values under the same lock the
// callbacks use; the report is built after the body is closed, but a transport
// goroutine is not something this package can observe finishing.
func (t *trace) tlsInfo() *TLSInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.tlsState == nil {
		return nil
	}
	return &TLSInfo{
		Version:    tls.VersionName(t.tlsState.Version),
		Cipher:     tls.CipherSuiteName(t.tlsState.CipherSuite),
		ServerName: t.tlsState.ServerName,
		Protocol:   t.tlsState.NegotiatedProtocol,
	}
}

func (t *trace) remote() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.remoteAddr
}

// timings turns the recorded instants into the report's milliseconds. A phase
// whose callbacks never fired (an IP literal needs no DNS) is zero, not an
// error: the timeline simply has nothing to draw there.
func (t *trace) timings(start, end time.Time) Timings {
	t.mu.Lock()
	defer t.mu.Unlock()

	connected := t.connectDone
	if t.tlsDone.After(connected) {
		connected = t.tlsDone
	}
	serverFrom := t.wrote
	if serverFrom.IsZero() {
		serverFrom = connected
	}

	timings := Timings{
		DNS:           milliseconds(span(t.dnsStart, t.dnsDone)),
		Connect:       milliseconds(span(t.connectFrom, t.connectDone)),
		TLS:           milliseconds(span(t.tlsStart, t.tlsDone)),
		Server:        milliseconds(span(serverFrom, t.firstByte)),
		Transfer:      milliseconds(span(t.firstByte, end)),
		Total:         milliseconds(span(start, end)),
		NameLookup:    milliseconds(span(start, t.dnsDone)),
		PreTransfer:   milliseconds(span(start, connected)),
		StartTransfer: milliseconds(span(start, t.firstByte)),
	}
	return timings
}

// span is a non-negative duration between two recorded instants; a missing
// endpoint means the phase did not happen.
func span(from, to time.Time) time.Duration {
	if from.IsZero() || to.IsZero() || to.Before(from) {
		return 0
	}
	return to.Sub(from)
}

func milliseconds(value time.Duration) float64 {
	rounded := math.Round(float64(value)/float64(time.Millisecond)*10) / 10
	if rounded < 0 {
		return 0
	}
	return rounded
}

// drain reads up to limit bytes and reports whether more remained, without
// buffering the body anywhere.
func drain(body io.Reader, limit int64) (int64, bool, error) {
	read, err := io.CopyN(io.Discard, body, limit)
	if err == nil {
		var probe [1]byte
		extra, moreErr := body.Read(probe[:])
		if moreErr != nil && !errors.Is(moreErr, io.EOF) {
			return read, false, moreErr
		}
		return read, extra > 0, nil
	}
	if errors.Is(err, io.EOF) {
		return read, false, nil
	}
	return read, false, err
}

func responseHeaders(header http.Header) []Header {
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	headers := make([]Header, 0, len(names))
	for _, name := range names {
		for _, value := range header.Values(name) {
			headers = append(headers, Header{
				Name:  name,
				Value: truncate(value, maxHeaderValue),
			})
		}
	}
	return headers
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "…"
}

// describe turns a transport error into a sentence the page can show without
// leaking the URL (which may carry a token) or a library stack.
func describe(err error, timeout time.Duration) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		err = urlErr.Err
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled), osTimeout(err):
		return fmt.Errorf("请求超时（%s）", formatDuration(timeout))
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		name := strings.TrimSpace(dnsErr.Name)
		if name == "" {
			return errors.New("无法解析域名")
		}
		return fmt.Errorf("无法解析域名 %s", name)
	}
	var authority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalid x509.CertificateInvalidError
	if errors.As(err, &authority) || errors.As(err, &hostname) || errors.As(err, &invalid) {
		return errors.New("TLS 证书校验失败，对方证书不受信任或不匹配")
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return errors.New("对方拒绝了连接（端口没有服务在监听）")
	}
	if errors.Is(err, syscall.ECONNRESET) {
		return errors.New("连接被对方重置")
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return errors.New("网络不可达")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("请求超时（%s）", formatDuration(timeout))
	}
	detail := strings.TrimSpace(strings.SplitN(err.Error(), "\n", 2)[0])
	if detail == "" {
		detail = "未知错误"
	}
	return fmt.Errorf("请求失败：%s", detail)
}

type timeoutError interface{ Timeout() bool }

func osTimeout(err error) bool {
	timeout, ok := err.(timeoutError)
	return ok && timeout.Timeout()
}

func formatDuration(value time.Duration) string {
	if value%time.Second == 0 {
		return fmt.Sprintf("%d 秒", int(value/time.Second))
	}
	return value.Round(100 * time.Millisecond).String()
}
