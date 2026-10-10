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
    "force": {"type": "boolean", "default": false, "description": "Discard any existing session (stored and in the browser profile) and mint a new one."}
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

	addDomainSchema = `{
  "type": "object",
  "properties": {
    "name": {"type": "string", "description": "Domain name: lowercase letters, digits, '.', '_' or '-'. Use the suggestion's name."},
    "base_url": {"type": "string", "description": "Scheme and host (and port) of the API, e.g. https://api.example.com."},
    "idp_hostnames": {"type": "array", "items": {"type": "string"}, "description": "Identity provider hostnames, from the suggestion if it has them. When omitted, add_domain asks the host itself, as albauth config add-domain does, and fills in the settings below."},
    "login_probe_path": {"type": "string", "description": "Path that starts the login (default \"/\"; found by add_domain for a forward-auth proxy)."},
    "cookie_name_prefix": {"type": "string", "description": "Session cookie family (default: the AWS load balancer's; found by add_domain for a forward-auth proxy)."},
    "treat_401_as_expired": {"type": "boolean", "default": false, "description": "The proxy answers 401 when there is no session (set by add_domain for a forward-auth proxy)."},
    "session_check_path": {"type": "string", "description": "Proxy endpoint that answers 2xx for a live session (found by add_domain for a forward-auth proxy)."},
    "allow_methods": {"type": "array", "items": {"type": "string", "enum": ["GET","HEAD","OPTIONS"]}, "default": ["GET"], "description": "Read-only methods only. Write methods are refused: only the user can grant them, outside the chat."}
  },
  "required": ["name", "base_url"]
}`
)

type toolSpec struct {
	name        string
	description string
	schema      string
}

func toolSpecs() []toolSpec {
	return []toolSpec{
		{ToolHTTPRequest, "Make an authenticated HTTP request to a configured domain behind a login (an AWS ALB OIDC rule, oauth2-proxy, a forward-auth proxy). Authentication is handled transparently; on first use for a domain a browser window will open for login. An absolute URL on an unconfigured host that sits behind a login fails with unknown_domain plus a 'suggestion' for add_domain.", httpRequestSchema},
		{ToolAuthLogin, "Open a browser to authenticate against a configured domain. Normally unnecessary — http_request triggers this automatically.", authLoginSchema},
		{ToolAuthStatus, "Report authentication state for one or all configured domains.", authStatusSchema},
		{ToolAuthLogout, "Delete the stored session for a domain. Does not log the user out of the identity provider.", authLogoutSchema},
		{ToolListDomains, "List the domains this server can reach, with their base URLs, host match patterns and allowed methods.", listDomainsSchema},
		{ToolAddDomain, "Add a domain to the user's albauth config, read-only, and make it usable at once. ASK THE USER FIRST: call this only after they have said yes in the chat, normally with the name, base_url and any idp_hostnames of an unknown_domain 'suggestion'; it finds a forward-auth proxy's remaining settings itself. Write methods are refused; only the user can grant them, outside the chat.", addDomainSchema},
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
