// Command mypaste-httpstat is the HTTP timing surface's own runtime.
//
// Protocol v3 lets a UI package declare a runtime and placement-less internal
// commands (D-1084); only this package's page can reach `probe`, and it never
// appears in the command palette. The page hands over the URL it is showing
// and gets back one JSON report: the same request is traced once, no redirect
// is followed and nothing is retried.
//
// The runtime speaks the plugin v2 line protocol (PLUGINS.md section 4): one
// request line on stdin, one response line on stdout.
package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mypaste/com.mypaste.httpstat/src/internal/probe"
)

const (
	maxRequestBytes = 1 << 20
	errorCode       = "probe-failed"
)

// invocation is the plugin v2 request line, reduced to the fields this
// command reads. Unknown fields are ignored by design.
type invocation struct {
	ID             string `json:"id"`
	Method         string `json:"method"`
	CommandID      string `json:"commandId"`
	DeadlineUnixMs int64  `json:"deadlineUnixMs"`
	Input          *struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"input"`
}

// response is the one-line reply. Exactly one of result / error is set.
type response struct {
	ID     string       `json:"id"`
	OK     bool         `json:"ok"`
	Result *resultShape `json:"result,omitempty"`
	Error  *errorShape  `json:"error,omitempty"`
}

type resultShape struct {
	Output string `json:"output"`
}

type errorShape struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func main() {
	request, err := readRequest()
	if err != nil {
		respond(failure("", err.Error()))
		return
	}
	var call invocation
	if err := json.Unmarshal(request, &call); err != nil {
		respond(failure("", "无法解析调用请求"))
		return
	}
	if call.ID == "" {
		// The host matches responses by ID; an unnamed request cannot be
		// answered usefully.
		respond(failure("", "调用请求缺少请求 ID"))
		return
	}
	if call.CommandID != "probe" {
		respond(failure(call.ID, "不支持的计时操作"))
		return
	}
	text := ""
	if call.Input != nil {
		text = call.Input.Text
	}
	if strings.TrimSpace(text) == "" {
		respond(failure(call.ID, "这条内容不是一条可以计时的链接"))
		return
	}

	timeout := probe.DefaultTimeout
	if call.DeadlineUnixMs > 0 {
		remaining := time.Until(time.UnixMilli(call.DeadlineUnixMs))
		if remaining <= 0 {
			respond(failure(call.ID, "调用已超时"))
			return
		}
		// Leave room to write the answer before the host's own deadline.
		if usable := remaining - 250*time.Millisecond; usable < timeout {
			if usable < 500*time.Millisecond {
				usable = 500 * time.Millisecond
			}
			timeout = usable
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	report, err := probe.Probe(ctx, text, probe.Options{Timeout: timeout})
	if err != nil {
		respond(failure(call.ID, err.Error()))
		return
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		respond(failure(call.ID, "无法生成计时结果"))
		return
	}
	respond(response{
		ID:     call.ID,
		OK:     true,
		Result: &resultShape{Output: string(encoded)},
	})
}

func failure(id string, message string) response {
	return response{ID: id, OK: false, Error: &errorShape{Code: errorCode, Message: message}}
}

func respond(value response) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return
	}
	_, _ = os.Stdout.Write(append(encoded, '\n'))
}

func readRequest() ([]byte, error) {
	reader := bufio.NewReaderSize(os.Stdin, 64*1024)
	var buffer bytes.Buffer
	for {
		chunk, err := reader.ReadSlice('\n')
		if buffer.Len()+len(chunk) > maxRequestBytes {
			return nil, errors.New("请求过大")
		}
		buffer.Write(chunk)
		if err == nil {
			return bytes.TrimSpace(buffer.Bytes()), nil
		}
		if !errors.Is(err, bufio.ErrBufferFull) {
			if buffer.Len() > 0 {
				return bytes.TrimSpace(buffer.Bytes()), nil
			}
			return nil, fmt.Errorf("读取请求失败：%w", err)
		}
	}
}
