// Package cli implements albauth's command-line surface.
//
// The binary is primarily an MCP server, but a few subcommands exist for setup
// and for machines where no browser is available. Everything here takes its
// streams and environment as parameters rather than reaching for globals, so
// the whole surface is testable without a subprocess.
package cli

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"albauth/internal/auth"
	"albauth/internal/browser"
	"albauth/internal/config"
	"albauth/internal/httpx"
	"albauth/internal/logx"
	"albauth/internal/mcpserver"
	"albauth/internal/session"
)

// Env is everything the CLI touches outside its own package. Supplying it makes
// every command runnable in a test with no process, no filesystem writes
// outside a temp dir, and no real browser.
type Env struct {
	Args    []string
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
	Getenv  func(string) string
	Now     func() time.Time
	Version string

	// Loginer performs interactive logins. Nil means "build the real
	// browser-driven one", which is what the binary does.
	Loginer auth.Loginer
}

const usage = `albauth — an MCP server for APIs behind an ALB OIDC listener rule.

Usage:
  albauth [flags] <command> [args]

Commands:
  serve                                  run the stdio MCP server (default)
  auth login <domain>                    run the browser login flow
  auth status [<domain>]                 show authentication state
  auth logout <domain> [--clear-browser-profile]
                                         delete the stored session
  auth import <domain>                   paste cookies from another machine
  config validate                        parse and validate the config
  config path                            print the resolved config path
  version                                print the version

Flags:
  --config <path>       config file to use
  --log-level <level>   error | warn | info | debug
`

// Run executes one command and returns the process exit code.
//
// It never calls os.Exit: main does that, so tests can assert on the code.
func Run(ctx context.Context, env Env) int {
	env = withDefaults(env)

	flags := flag.NewFlagSet("albauth", flag.ContinueOnError)
	flags.SetOutput(env.Stderr)
	flags.Usage = func() { fmt.Fprint(env.Stderr, usage) }
	configPath := flags.String("config", "", "path to config.toml")
	logLevel := flags.String("log-level", "", "error, warn, info or debug")
	if err := flags.Parse(env.Args); err != nil {
		// The flag package prints usage itself for -h and --help; that is a
		// successful help request, not a misuse.
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}

	args := flags.Args()
	command := "serve"
	if len(args) > 0 {
		command = args[0]
		args = args[1:]
	}

	app := &app{env: env, configPath: *configPath, logLevel: *logLevel}
	err := app.dispatch(ctx, command, args)
	if err == nil {
		return 0
	}
	if errors.Is(err, errUsage) {
		fmt.Fprint(env.Stderr, usage)
		return 2
	}
	fmt.Fprintf(env.Stderr, "albauth: %v\n", err)
	return 1
}

func withDefaults(env Env) Env {
	if env.Stdin == nil {
		env.Stdin = strings.NewReader("")
	}
	if env.Stdout == nil {
		env.Stdout = io.Discard
	}
	if env.Stderr == nil {
		env.Stderr = io.Discard
	}
	if env.Getenv == nil {
		env.Getenv = os.Getenv
	}
	if env.Now == nil {
		env.Now = time.Now
	}
	if env.Version == "" {
		env.Version = "dev"
	}
	return env
}

var errUsage = errors.New("usage")

// Indirected so the tests can drive the failure branches of path resolution
// and store selection without depending on the machine they run on.
var (
	configResolvePath = config.ResolvePath
	stateDirPath      = config.StateDir
	sessionFilePath   = config.SessionFilePath
	openStore         = session.Open
)

type app struct {
	env        Env
	configPath string
	logLevel   string
}

func (a *app) dispatch(ctx context.Context, command string, args []string) error {
	switch command {
	case "serve":
		return a.serve(ctx)
	case "version":
		fmt.Fprintln(a.env.Stdout, a.env.Version)
		return nil
	case "auth":
		return a.auth(ctx, args)
	case "config":
		return a.config(args)
	case "help", "-h", "--help":
		fmt.Fprint(a.env.Stderr, usage)
		return nil
	default:
		return fmt.Errorf("unknown command %q%w", command, wrapUsage())
	}
}

func wrapUsage() error { return fmt.Errorf("%w", errUsage) }

func (a *app) auth(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "login":
		return a.authLogin(ctx, rest)
	case "status":
		return a.authStatus(rest)
	case "logout":
		return a.authLogout(rest)
	case "import":
		return a.authImport(rest)
	default:
		return fmt.Errorf("unknown auth subcommand %q%w", sub, wrapUsage())
	}
}

func (a *app) config(args []string) error {
	if len(args) == 0 {
		return errUsage
	}
	switch args[0] {
	case "validate":
		rt, err := a.build()
		if err != nil {
			return err
		}
		fmt.Fprintf(a.env.Stdout, "config %s is valid: %d domain(s) configured\n",
			rt.cfg.Path, len(rt.cfg.Domains))
		return nil
	case "path":
		path, err := configResolvePath(a.configPath, a.env.Getenv)
		if err != nil {
			return err
		}
		fmt.Fprintln(a.env.Stdout, path)
		return nil
	default:
		return fmt.Errorf("unknown config subcommand %q%w", args[0], wrapUsage())
	}
}

func (a *app) serve(ctx context.Context) error {
	rt, err := a.build()
	if err != nil {
		return err
	}
	rt.log.Info("serving MCP over stdio (%d domain(s), %s storage)",
		len(rt.cfg.Domains), rt.store.Backend())
	return mcpserver.Serve(ctx, mcpserver.New(rt.deps, a.env.Version), a.env.Stdin, a.env.Stdout)
}

func (a *app) authLogin(ctx context.Context, args []string) error {
	set := flag.NewFlagSet("auth login", flag.ContinueOnError)
	set.SetOutput(a.env.Stderr)
	force := set.Bool("force", false, "discard any existing session first")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 1 {
		return fmt.Errorf("auth login needs exactly one domain%w", wrapUsage())
	}
	rt, err := a.build()
	if err != nil {
		return err
	}
	domain, err := rt.domain(set.Arg(0))
	if err != nil {
		return err
	}

	var s *session.Session
	if *force {
		s, err = rt.mgr.ForceLogin(ctx, domain)
	} else {
		s, err = rt.mgr.Ensure(ctx, domain)
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(a.env.Stdout, "%s: authenticated, %d cookie(s), expires %s\n",
		domain.Name, len(s.Cookies), expiryText(s.ExpiresAt()))
	return nil
}

func (a *app) authStatus(args []string) error {
	if len(args) > 1 {
		return fmt.Errorf("auth status takes at most one domain%w", wrapUsage())
	}
	rt, err := a.build()
	if err != nil {
		return err
	}
	names := rt.cfg.DomainNames()
	if len(args) == 1 {
		if _, err := rt.domain(args[0]); err != nil {
			return err
		}
		names = []string{args[0]}
	}
	slices.Sort(names)

	tw := tabwriter.NewWriter(a.env.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "DOMAIN\tBASE URL\tSTATE\tEXPIRES\tSTORAGE")
	for _, name := range names {
		domain, _ := rt.cfg.Lookup(name)
		state, expires := "logged out", "-"
		s, storeErr := rt.mgr.Current(name)
		switch {
		case storeErr != nil:
			state = "error: " + storeErr.Error()
		case s != nil && s.Valid(a.env.Now()):
			state, expires = "authenticated", expiryText(s.ExpiresAt())
		case s != nil:
			state, expires = "expired", expiryText(s.ExpiresAt())
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", name, domain.BaseURL, state, expires, rt.store.Backend())
	}
	return tw.Flush()
}

func (a *app) authLogout(args []string) error {
	set := flag.NewFlagSet("auth logout", flag.ContinueOnError)
	set.SetOutput(a.env.Stderr)
	clearProfile := set.Bool("clear-browser-profile", false, "also delete the persistent browser profile")
	if err := set.Parse(args); err != nil {
		return err
	}
	if set.NArg() != 1 {
		return fmt.Errorf("auth logout needs exactly one domain%w", wrapUsage())
	}
	rt, err := a.build()
	if err != nil {
		return err
	}
	domain, err := rt.domain(set.Arg(0))
	if err != nil {
		return err
	}
	if err := rt.mgr.Logout(domain.Name); err != nil {
		return err
	}
	fmt.Fprintf(a.env.Stdout, "%s: session deleted\n", domain.Name)
	if *clearProfile {
		if err := rt.clearProfile(domain.Name); err != nil {
			return err
		}
		fmt.Fprintf(a.env.Stdout, "%s: browser profile deleted\n", domain.Name)
	}
	return nil
}

func (a *app) authImport(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("auth import needs exactly one domain%w", wrapUsage())
	}
	rt, err := a.build()
	if err != nil {
		return err
	}
	domain, err := rt.domain(args[0])
	if err != nil {
		return err
	}

	fmt.Fprintln(a.env.Stdout, auth.ImportInstructions(domain))
	reader := readSecret(a.env.Stdin)
	s, err := auth.ImportSession(reader, domain, a.env.Now())
	if err != nil {
		return err
	}
	if err := rt.mgr.Save(domain.Name, s); err != nil {
		return err
	}
	fmt.Fprintf(a.env.Stdout, "\n%s: imported %d cookie(s), assumed valid until %s\n",
		domain.Name, len(s.Cookies), expiryText(s.ExpiresAt()))
	return nil
}

func expiryText(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.UTC().Format(time.RFC3339)
}

// runtime bundles everything a command needs once the config is loaded.
type runtime struct {
	cfg      *config.Config
	log      *logx.Logger
	store    session.Store
	mgr      *auth.Manager
	deps     *mcpserver.Deps
	stateDir string
}

func (r *runtime) domain(name string) (*config.Domain, error) {
	d, ok := r.cfg.Lookup(name)
	if !ok {
		return nil, fmt.Errorf("unknown domain %q (configured: %s)",
			name, strings.Join(r.cfg.DomainNames(), ", "))
	}
	return d, nil
}

func (r *runtime) clearProfile(domainName string) error {
	dir := filepath.Join(r.stateDir, "browser", domainName)
	if err := os.RemoveAll(dir); err != nil {
		return fmt.Errorf("remove browser profile %s: %w", dir, err)
	}
	return nil
}

// build loads config and wires the object graph. Every command goes through it,
// so a config problem is reported the same way everywhere.
func (a *app) build() (*runtime, error) {
	path, err := configResolvePath(a.configPath, a.env.Getenv)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	if a.logLevel != "" {
		cfg.Settings.LogLevel = a.logLevel
	}
	level, err := logx.ParseLevel(cfg.Settings.LogLevel)
	if err != nil {
		return nil, err
	}
	log := logx.New(a.env.Stderr, level)

	stateDir, err := stateDirPath(a.env.Getenv)
	if err != nil {
		return nil, err
	}
	sessionPath, err := sessionFilePath(a.env.Getenv)
	if err != nil {
		return nil, err
	}
	store, err := openStore(cfg.Settings.Storage, sessionPath, log)
	if err != nil {
		return nil, err
	}

	loginer := a.env.Loginer
	if loginer == nil {
		loginer = browser.New()
	}
	mgr := auth.NewManager(auth.ManagerOptions{
		Store:   store,
		Loginer: loginer,
		Log:     log,
		Now:     a.env.Now,
		ProfileDir: func(domainName string) (string, error) {
			return filepath.Join(stateDir, "browser", domainName), nil
		},
	})

	rt := &runtime{cfg: cfg, log: log, store: store, mgr: mgr, stateDir: stateDir}
	rt.deps = &mcpserver.Deps{
		Config:              cfg,
		Auth:                mgr,
		Client:              httpx.NewClient(mgr, cfg.Settings.MaxResponseBytes),
		Now:                 a.env.Now,
		ClearBrowserProfile: rt.clearProfile,
	}
	return rt, nil
}
