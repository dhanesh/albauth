package mcpserver

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
)

func TestToolSpecsCoverTheDocumentedSurface(t *testing.T) {
	specs := toolSpecs()
	want := map[string]bool{
		ToolHTTPRequest: false, ToolAuthLogin: false, ToolAuthStatus: false,
		ToolAuthLogout: false, ToolListDomains: false, ToolAddDomain: false,
	}
	if len(specs) != len(want) {
		t.Fatalf("declared %d tools, want %d", len(specs), len(want))
	}
	for _, spec := range specs {
		if _, expected := want[spec.name]; !expected {
			t.Fatalf("unexpected tool %q", spec.name)
		}
		want[spec.name] = true
		if spec.description == "" {
			t.Fatalf("%s has no description", spec.name)
		}
		// The schema a client sees must be valid JSON Schema-shaped JSON.
		var schema map[string]any
		if err := json.Unmarshal([]byte(spec.schema), &schema); err != nil {
			t.Fatalf("%s schema is not valid JSON: %v", spec.name, err)
		}
		if schema["type"] != "object" {
			t.Fatalf("%s schema type = %v, want object", spec.name, schema["type"])
		}
	}
	for name, seen := range want {
		if !seen {
			t.Fatalf("tool %q was not declared", name)
		}
	}
}

func TestNewRegistersEveryTool(t *testing.T) {
	h := newHarness(t)
	srv := New(h.deps, "1.2.3")
	if srv == nil {
		t.Fatal("New returned nil")
	}

	result := srv.HandleMessage(t.Context(), []byte(
		`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, name := range []string{ToolHTTPRequest, ToolAuthLogin, ToolAuthStatus, ToolAuthLogout, ToolListDomains, ToolAddDomain} {
		if !strings.Contains(string(encoded), `"`+name+`"`) {
			t.Fatalf("tools/list did not advertise %q: %s", name, encoded)
		}
	}
}

func TestHandlerForReturnsAToolResult(t *testing.T) {
	h := newHarness(t)
	handler := handlerFor(h.deps, ToolListDomains)

	result, err := handler(t.Context(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	if result.IsError {
		t.Fatalf("list_domains should succeed, got %+v", result)
	}
	text := textOf(t, result)
	if !strings.Contains(text, "internal-api") {
		t.Fatalf("result = %q", text)
	}
}

// A failure is a tool result carrying the documented error payload, not a
// protocol error, so the model can read the code and hint and act on them.
func TestHandlerForRendersFailuresAsToolResults(t *testing.T) {
	h := newHarness(t)
	handler := handlerFor(h.deps, ToolAuthLogout)

	result, err := handler(t.Context(), mcp.CallToolRequest{})
	if err != nil {
		t.Fatalf("a tool failure must not be a protocol error: %v", err)
	}
	if !result.IsError {
		t.Fatal("the result should be marked as an error")
	}
	var payload map[string]string
	if err := json.Unmarshal([]byte(textOf(t, result)), &payload); err != nil {
		t.Fatalf("error payload is not JSON: %v (%s)", err, textOf(t, result))
	}
	if payload["error"] == "" || payload["message"] == "" {
		t.Fatalf("payload = %v", payload)
	}
}

func TestHandlerForRejectsAnUnknownTool(t *testing.T) {
	h := newHarness(t)
	result, err := handlerFor(h.deps, "not_a_tool")(t.Context(), mcp.CallToolRequest{})
	if err != nil || !result.IsError {
		t.Fatalf("result = %+v, err = %v", result, err)
	}
}

// Serve speaks real JSON-RPC over the streams it is given, and writes nothing
// else to the output stream.
func TestServeSpeaksJSONRPCOverTheGivenStreams(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	inReader, inWriter := io.Pipe()
	outReader, outWriter := io.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(ctx, New(h.deps, "test"), inReader, outWriter) }()

	send := func(msg string) {
		if _, err := io.WriteString(inWriter, msg+"\n"); err != nil {
			t.Errorf("write: %v", err)
		}
	}
	lines := bufio.NewScanner(outReader)
	readLine := func() string {
		if !lines.Scan() {
			t.Fatalf("no response: %v", lines.Err())
		}
		return lines.Text()
	}

	send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`)
	if got := readLine(); !strings.Contains(got, `"result"`) {
		t.Fatalf("initialize response = %s", got)
	}

	send(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"list_domains","arguments":{}}}`)
	response := readLine()
	if !strings.Contains(response, "internal-api") {
		t.Fatalf("list_domains response = %s", response)
	}
	// Every line on the output stream must be a JSON-RPC message.
	var envelope map[string]any
	if err := json.Unmarshal([]byte(response), &envelope); err != nil {
		t.Fatalf("output is not JSON-RPC: %v (%s)", err, response)
	}
	if envelope["jsonrpc"] != "2.0" {
		t.Fatalf("envelope = %v", envelope)
	}

	cancel()
	_ = inWriter.Close()
	_ = outWriter.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return after its context was cancelled")
	}
}

func textOf(t *testing.T, result *mcp.CallToolResult) string {
	t.Helper()
	if len(result.Content) == 0 {
		t.Fatal("result carries no content")
	}
	text, ok := mcp.AsTextContent(result.Content[0])
	if !ok {
		t.Fatalf("content is not text: %T", result.Content[0])
	}
	return text.Text
}
