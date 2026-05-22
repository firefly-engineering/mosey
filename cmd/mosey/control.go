// runControl implements `mosey control` — admin operations against
// the vterm's /mosey/control/ stream. See main.go for the binary-
// level usage.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"text/tabwriter"
	"time"

	"google.golang.org/protobuf/encoding/protodelim"

	"github.com/firefly-engineering/mosey/api"
	"github.com/firefly-engineering/mosey/auth"
	"github.com/firefly-engineering/mosey/cmd/internal/certflags"
	"github.com/firefly-engineering/mosey/transport"
	httpbackend "github.com/firefly-engineering/mosey/transport/http2"
	libp2pbackend "github.com/firefly-engineering/mosey/transport/libp2p"
	unixbackend "github.com/firefly-engineering/mosey/transport/unix"
	wsbackend "github.com/firefly-engineering/mosey/transport/websocket"
)

// runControl dispatches `mosey control <subcmd>`. Each subcommand
// takes its own flag set (auth + listen options match attach so the
// admin flow can reuse the same credentials).
func runControl(args []string, stdout, stderr *os.File) int {
	if len(args) < 1 {
		controlUsage(stderr)
		return 2
	}
	switch args[0] {
	case "list-clients":
		return cmdControlListClients(args[1:], stdout, stderr)
	case "promote":
		return cmdControlPromote(args[1:], stderr)
	case "kick":
		return cmdControlKick(args[1:], stderr)
	case "demote":
		return cmdControlDemote(args[1:], stderr)
	case "set-mode":
		return cmdControlSetMode(args[1:], stderr)
	case "-h", "--help", "help":
		controlUsage(stdout)
		return 0
	default:
		fmt.Fprintf(stderr, "mosey control: unknown subcommand %q\n", args[0])
		controlUsage(stderr)
		return 2
	}
}

func controlUsage(w *os.File) {
	fmt.Fprintln(w, `mosey control: admin operations against the vterm control stream

Subcommands (all take the same auth flags as `+"`mosey attach`"+`):
  list-clients ENDPOINT
  promote      ENDPOINT CLIENT_ID
  kick         ENDPOINT CLIENT_ID
  demote       ENDPOINT
  set-mode     ENDPOINT MODE   (supersede | exclusive | primary-observer | multi-write)`)
}

// controlFlags is the shared flag bundle for every control
// subcommand: auth credentials + transport tunables.
type controlFlags struct {
	secret      string
	noBootstrap bool
	insecureTLS bool
	certCfg     certflags.Flags
}

func (cf *controlFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&cf.secret, "secret", "", "shared PSK; mutually exclusive with --cert. Must match the vterm side.")
	fs.BoolVar(&cf.noBootstrap, "no-p2p-bootstrap", false, "skip the IPFS public bootstrap set; useful for LAN-only / offline testing")
	fs.BoolVar(&cf.insecureTLS, "insecure-tls", false, "for https:// endpoints, skip server certificate verification (self-signed dev only)")
	cf.certCfg.Register(fs)
}

func (cf *controlFlags) authenticator() (auth.Authenticator, error) {
	if cf.secret == "" && !cf.certCfg.Configured() {
		return nil, errors.New("either --secret (PSK) or --cert/--key/--master-pub (workspace cert) is required")
	}
	if cf.secret != "" && cf.certCfg.Configured() {
		return nil, errors.New("--secret and --cert are mutually exclusive (pick one auth model)")
	}
	if cf.certCfg.Configured() {
		return cf.certCfg.Build()
	}
	return auth.NewPSKAuth(cf.secret)
}

// dialControl wires up a one-shot control client: build dial-only
// libp2p + http2 backends, wrap with auth, dial the control proto.
// Returns the open stream and a cleanup func the caller must invoke.
func dialControl(ctx context.Context, cf *controlFlags, target string) (transport.Stream, func(), error) {
	authenticator, err := cf.authenticator()
	if err != nil {
		return nil, nil, err
	}

	libp2pBackend, err := libp2pbackend.New(ctx, libp2pOptsForAttach(cf.noBootstrap))
	if err != nil {
		return nil, nil, fmt.Errorf("libp2p backend: %w", err)
	}
	httpBackend, err := httpbackend.New(ctx, httpbackend.Options{InsecureSkipVerify: cf.insecureTLS})
	if err != nil {
		_ = libp2pBackend.Close()
		return nil, nil, fmt.Errorf("http2 backend: %w", err)
	}
	unixBackend, err := unixbackend.New(ctx, unixbackend.Options{})
	if err != nil {
		_ = httpBackend.Close()
		_ = libp2pBackend.Close()
		return nil, nil, fmt.Errorf("unix backend: %w", err)
	}
	wsBackend, err := wsbackend.New(ctx, wsbackend.Options{InsecureSkipVerify: cf.insecureTLS})
	if err != nil {
		_ = unixBackend.Close()
		_ = httpBackend.Close()
		_ = libp2pBackend.Close()
		return nil, nil, fmt.Errorf("websocket backend: %w", err)
	}
	multi, err := transport.Multi(libp2pBackend, httpBackend, unixBackend, wsBackend)
	if err != nil {
		_ = wsBackend.Close()
		_ = unixBackend.Close()
		_ = httpBackend.Close()
		_ = libp2pBackend.Close()
		return nil, nil, err
	}
	authed := auth.Wrap(multi, authenticator)
	s, err := authed.Dial(ctx, target, api.ProtoControl)
	if err != nil {
		_ = wsBackend.Close()
		_ = unixBackend.Close()
		_ = httpBackend.Close()
		_ = libp2pBackend.Close()
		return nil, nil, fmt.Errorf("open %s: %w", api.ProtoControl, err)
	}
	cleanup := func() {
		_ = s.Close()
		_ = wsBackend.Close()
		_ = unixBackend.Close()
		_ = httpBackend.Close()
		_ = libp2pBackend.Close()
	}
	return s, cleanup, nil
}

// parseControlArgs handles the common positional pattern: ENDPOINT
// plus optional trailing positional args. nWantPos is the number of
// trailing positional args (after ENDPOINT) that the subcommand
// requires.
func parseControlArgs(name string, args []string, nWantPos int, stderr *os.File) (cf *controlFlags, target string, pos []string, code int) {
	fs := flag.NewFlagSet("control "+name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	cf = &controlFlags{}
	cf.register(fs)
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil, "", nil, 0
		}
		return nil, "", nil, 2
	}
	if fs.NArg() != 1+nWantPos {
		fmt.Fprintf(stderr, "mosey control %s: expected ENDPOINT", name)
		for i := 0; i < nWantPos; i++ {
			fmt.Fprintf(stderr, " ARG%d", i+1)
		}
		fmt.Fprintln(stderr)
		return nil, "", nil, 2
	}
	target = fs.Arg(0)
	if nWantPos > 0 {
		pos = fs.Args()[1:]
	}
	return cf, target, pos, -1
}

// signalContext wraps a fresh context with SIGINT/SIGTERM handling
// and a sensible default timeout.
func signalContext(timeout time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	ctx, cancelTimeout := context.WithTimeout(ctx, timeout)
	return ctx, func() {
		cancelTimeout()
		cancel()
	}
}

func cmdControlListClients(args []string, stdout, stderr *os.File) int {
	cf, target, _, code := parseControlArgs("list-clients", args, 0, stderr)
	if code >= 0 {
		return code
	}
	ctx, cancel := signalContext(10 * time.Second)
	defer cancel()
	stream, cleanup, err := dialControl(ctx, cf, target)
	if err != nil {
		fmt.Fprintln(stderr, "mosey control list-clients:", err)
		return 1
	}
	defer cleanup()
	if _, err := protodelim.MarshalTo(stream, &api.ControlMessage{
		Payload: &api.ControlMessage_ListClients{ListClients: &api.ListClients{}},
	}); err != nil {
		fmt.Fprintln(stderr, "mosey control list-clients: send:", err)
		return 1
	}
	var msg api.ControlMessage
	if err := protodelim.UnmarshalFrom(bufio.NewReader(stream), &msg); err != nil {
		fmt.Fprintln(stderr, "mosey control list-clients: read response:", err)
		return 1
	}
	list := msg.GetClientList()
	if list == nil {
		fmt.Fprintf(stderr, "mosey control list-clients: unexpected response %T\n", msg.Payload)
		return 1
	}
	w := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tLABEL\tWRITE\tCOLSxROWS")
	for _, c := range list.Clients {
		write := "no"
		if c.CanWrite {
			write = "yes"
		}
		fmt.Fprintf(w, "%d\t%s\t%s\t%dx%d\n", c.ClientId, c.Label, write, c.Cols, c.Rows)
	}
	_ = w.Flush()
	return 0
}

func cmdControlPromote(args []string, stderr *os.File) int {
	cf, target, pos, code := parseControlArgs("promote", args, 1, stderr)
	if code >= 0 {
		return code
	}
	id, err := strconv.ParseInt(pos[0], 10, 64)
	if err != nil {
		fmt.Fprintln(stderr, "mosey control promote: CLIENT_ID must be an integer")
		return 2
	}
	return sendOneShot(cf, target, &api.ControlMessage{
		Payload: &api.ControlMessage_Promote{Promote: &api.Promote{ClientId: id}},
	}, "promote", stderr)
}

func cmdControlKick(args []string, stderr *os.File) int {
	cf, target, pos, code := parseControlArgs("kick", args, 1, stderr)
	if code >= 0 {
		return code
	}
	id, err := strconv.ParseInt(pos[0], 10, 64)
	if err != nil {
		fmt.Fprintln(stderr, "mosey control kick: CLIENT_ID must be an integer")
		return 2
	}
	return sendOneShot(cf, target, &api.ControlMessage{
		Payload: &api.ControlMessage_Kick{Kick: &api.Kick{ClientId: id}},
	}, "kick", stderr)
}

func cmdControlDemote(args []string, stderr *os.File) int {
	cf, target, _, code := parseControlArgs("demote", args, 0, stderr)
	if code >= 0 {
		return code
	}
	return sendOneShot(cf, target, &api.ControlMessage{
		Payload: &api.ControlMessage_Demote{Demote: &api.Demote{}},
	}, "demote", stderr)
}

func cmdControlSetMode(args []string, stderr *os.File) int {
	cf, target, pos, code := parseControlArgs("set-mode", args, 1, stderr)
	if code >= 0 {
		return code
	}
	kind, err := parseSetModeKind(pos[0])
	if err != nil {
		fmt.Fprintln(stderr, "mosey control set-mode:", err)
		return 2
	}
	return sendOneShot(cf, target, &api.ControlMessage{
		Payload: &api.ControlMessage_SetMode{SetMode: &api.SetMode{Kind: kind}},
	}, "set-mode", stderr)
}

func parseSetModeKind(s string) (api.SetMode_Kind, error) {
	switch s {
	case "supersede":
		return api.SetMode_KIND_SUPERSEDE, nil
	case "exclusive":
		return api.SetMode_KIND_EXCLUSIVE, nil
	case "primary-observer":
		return api.SetMode_KIND_PRIMARY_OBSERVER, nil
	case "multi-write":
		return api.SetMode_KIND_MULTI_WRITE, nil
	default:
		return api.SetMode_KIND_UNSPECIFIED, fmt.Errorf("unknown mode %q (have: supersede, exclusive, primary-observer, multi-write)", s)
	}
}

// sendOneShot dials, writes one message, closes. Used for the
// fire-and-forget admin commands (the server ignores them silently
// when the caller lacks the required cap, by design — no
// confirmation is sent back).
func sendOneShot(cf *controlFlags, target string, msg *api.ControlMessage, name string, stderr *os.File) int {
	ctx, cancel := signalContext(10 * time.Second)
	defer cancel()
	stream, cleanup, err := dialControl(ctx, cf, target)
	if err != nil {
		fmt.Fprintln(stderr, "mosey control "+name+":", err)
		return 1
	}
	defer cleanup()
	if _, err := protodelim.MarshalTo(stream, msg); err != nil {
		fmt.Fprintln(stderr, "mosey control "+name+": send:", err)
		return 1
	}
	return 0
}
