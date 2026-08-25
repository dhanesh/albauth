package mcpserver

import (
	"context"
	"encoding/json"
	"io"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// ServerName is how albauth identifies itself to MCP clients.
const ServerName = "albauth"

// Tool schemas are declared as raw JSON so that what a client sees is exactly
// what the specification documents, rather than whatever a builder API happens
// to emit.
const (
	httpRequestSchema = `{
  "type": "object",
  "properties": {
    "url": {"type": "string", "description": "Full URL (https://api.example.com/v1/users) or a path (/v1/users) when 'domain' is given."},
    "domain": {"type": "string", "description": "Configured domain name. Optional if 'url' is absolute and matches a configured domain."},
    "method": {"type": "string", "enum": ["GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"], "default": "GET"},
    "query": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Query parameters, appended to the URL."},
    "headers": {"type": "object", "additionalProperties": {"type": "string"}},
    "body": {"type": "string", "description": "Raw request body. For JSON, pass a JSON string and set Content-Type."}
  },
  "required": ["url"]
}`

	authLoginSchema = `{
  "type": "object",
  "properties": {
    "domain": {"type": "string"},
    "force": {"type": "boolean", "default": false, "description": "Discard any existing session and re-authenticate."}
  },
  "required": ["domain"]
}`

	authStatusSchema = `{"type": "object", "properties": {"domain": {"type": "string"}}}`

	authLogoutSchema = `{
  "type": "object",
  "properties": {
    "domain": {"type": "string"},
    "clear_browser_profile": {"type": "boolean", "default": false, "description": "Also delete the persistent browser profile, forcing a full login next time."}
  },
  "required": ["domain"]
}`

	listDomainsSchema = `{"type": "object", "properties": {}}`
)

type toolSpec struct {
	name        string
	description string
	schema      string
}

func toolSpecs() []toolSpec {
	return []toolSpec{
		{ToolHTTPRequest, "Make an authenticated HTTP request to a configured domain behind an ALB OIDC listener rule. Authentication is handled transparently; on first use for a domain a browser window will open for login.", httpRequestSchema},
		{ToolAuthLogin, "Open a browser to authenticate against a configured domain. Normally unnecessary — http_request triggers this automatically.", authLoginSchema},
		{ToolAuthStatus, "Report authentication state for one or all configured domains.", authStatusSchema},
		{ToolAuthLogout, "Delete the stored session for a domain. Does not log the user out of the identity provider.", authLogoutSchema},
		{ToolListDomains, "List the domains this server can reach, with their base URLs, host match patterns and allowed methods.", listDomainsSchema},
	}
}

// New builds an MCP server with albauth's tools registered.
func New(deps *Deps, version string) *server.MCPServer {
	s := server.NewMCPServer(ServerName, version, server.WithToolCapabilities(false))
	for _, spec := range toolSpecs() {
		s.AddTool(
			mcp.NewToolWithRawSchema(spec.name, spec.description, json.RawMessage(spec.schema)),
			handlerFor(deps, spec.name),
		)
	}
	return s
}

// handlerFor adapts a tool name to an mcp-go handler.
//
// Failures come back as tool results rather than protocol errors, so the model
// receives the documented {error, message, hint} payload and can act on it.
func handlerFor(deps *Deps, name string) server.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		result, err := deps.Handle(ctx, name, req.GetArguments())
		if err != nil {
			return mcp.NewToolResultError(RenderError(err)), nil
		}
		// Every value Handle returns is built from strings, numbers, booleans
		// and maps of those, so encoding cannot fail.
		encoded, _ := json.MarshalIndent(result, "", "  ")
		return mcp.NewToolResultText(string(encoded)), nil
	}
}

// Serve runs the MCP protocol over the given streams until the client
// disconnects or ctx is cancelled.
//
// In production the streams are os.Stdin and os.Stdout. stdout is the protocol
// channel and nothing else may write to it; every log line in albauth goes to
// stderr for exactly this reason. Taking the streams as parameters is also what
// lets the tests drive a real protocol conversation in-process.
func Serve(ctx context.Context, s *server.MCPServer, in io.Reader, out io.Writer) error {
	return server.NewStdioServer(s).Listen(ctx, in, out)
}
