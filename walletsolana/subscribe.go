package walletsolana

// accountSubscribe push path. The asymmetric-refresh design
// (docs/src/wallet-auth.md): subscribe over WebSocket to the Session
// account and each known Grant account so revocation / transfer / epoch
// bump propagate in ~one slot. A notification is only a *trigger* — we
// re-Refresh authoritatively rather than apply deltas. New grants and any
// missed notifications are healed by the backstop poll in Run; a dead
// socket surfaces as a read/write error and reconnects with backoff.

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gorilla/websocket"
)

// wsConn is the slice of *websocket.Conn the watcher needs; an interface
// so tests can inject a fake without a real socket.
type wsConn interface {
	WriteJSON(v any) error
	ReadJSON(v any) error
	Close() error
}

// wsDialer opens a WebSocket to url.
type wsDialer func(ctx context.Context, url string) (wsConn, error)

func dialGorilla(ctx context.Context, url string) (wsConn, error) {
	c, _, err := websocket.DefaultDialer.DialContext(ctx, url, nil)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// deriveWSEndpoint scheme-swaps an http(s) RPC URL to its ws(s) form
// (correct for public clusters, which serve WS on the same host). Returns
// "" for anything else; callers can set Options.WSEndpoint explicitly.
func deriveWSEndpoint(rpc string) string {
	switch {
	case strings.HasPrefix(rpc, "https://"):
		return "wss://" + strings.TrimPrefix(rpc, "https://")
	case strings.HasPrefix(rpc, "http://"):
		return "ws://" + strings.TrimPrefix(rpc, "http://")
	default:
		return ""
	}
}

// watch maintains the subscription connection for the lifetime of ctx,
// reconnecting with capped exponential backoff. Each notification signals
// refreshNow (coalesced). The poll loop keeps serving throughout.
func (s *Source) watch(ctx context.Context, refreshNow chan<- struct{}, onError func(error)) {
	const maxBackoff = 30 * time.Second
	backoff := time.Second
	for {
		if ctx.Err() != nil {
			return
		}
		conn, err := s.dialWS(ctx, s.wsEndpoint)
		if err != nil {
			if onError != nil {
				onError(fmt.Errorf("walletsolana: ws dial: %w", err))
			}
		} else {
			start := s.now()
			runErr := s.runConn(ctx, conn, refreshNow)
			_ = conn.Close()
			if ctx.Err() != nil {
				return
			}
			if runErr != nil && onError != nil {
				onError(fmt.Errorf("walletsolana: ws: %w", runErr))
			}
			if s.now().Sub(start) > maxBackoff {
				backoff = time.Second // the connection was healthy; reset
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > maxBackoff {
			backoff = maxBackoff
		}
	}
}

// runConn subscribes to the current targets, reads notifications until the
// socket or ctx ends, and re-subscribes to newly-discovered grant accounts
// on each reconcile tick.
func (s *Source) runConn(ctx context.Context, conn wsConn, refreshNow chan<- struct{}) error {
	subscribed := make(map[string]bool)
	id := 0
	reconcile := func() error {
		for _, addr := range s.subscribeTargets() {
			if subscribed[addr] {
				continue
			}
			id++
			err := conn.WriteJSON(map[string]any{
				"jsonrpc": "2.0",
				"id":      id,
				"method":  "accountSubscribe",
				"params":  []any{addr, map[string]any{"encoding": "base64", "commitment": s.commitment}},
			})
			if err != nil {
				return err
			}
			subscribed[addr] = true
		}
		return nil
	}
	if err := reconcile(); err != nil {
		return err
	}

	readErr := make(chan error, 1)
	go func() {
		for {
			var msg struct {
				Method string `json:"method"`
			}
			if err := conn.ReadJSON(&msg); err != nil {
				readErr <- err
				return
			}
			if msg.Method == "accountNotification" {
				select {
				case refreshNow <- struct{}{}:
				default: // a refresh is already pending; coalesce
				}
			}
		}
	}()

	t := time.NewTicker(s.reconcileInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readErr:
			return err
		case <-t.C:
			if err := reconcile(); err != nil {
				return err
			}
		}
	}
}
