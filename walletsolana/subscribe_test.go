package walletsolana

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/wallet"
)

// fakeWS is an in-memory wsConn: it records accountSubscribe targets and
// delivers a notification to ReadJSON when the test pushes to notify.
type fakeWS struct {
	subs    chan string
	notify  chan struct{}
	closeCh chan struct{}
	once    sync.Once
}

func newFakeWS() *fakeWS {
	return &fakeWS{
		subs:    make(chan string, 16),
		notify:  make(chan struct{}, 1),
		closeCh: make(chan struct{}),
	}
}

func (f *fakeWS) WriteJSON(v any) error {
	m, ok := v.(map[string]any)
	if ok && m["method"] == "accountSubscribe" {
		f.subs <- m["params"].([]any)[0].(string)
	}
	return nil
}

func (f *fakeWS) ReadJSON(v any) error {
	select {
	case <-f.closeCh:
		return errors.New("closed")
	case <-f.notify:
		b, _ := json.Marshal(map[string]any{
			"method": "accountNotification",
			"params": map[string]any{"subscription": 1},
		})
		return json.Unmarshal(b, v)
	}
}

func (f *fakeWS) Close() error {
	f.once.Do(func() { close(f.closeCh) })
	return nil
}

func TestRunPushTriggersRefresh(t *testing.T) {
	now := func() time.Time { return time.Unix(6_000_000, 0) }
	sessionKey, owner, viewer := key(t), key(t), key(t)
	sessAddr, grantAddr := key(t), key(t)
	sessAddrStr := wallet.Address(sessAddr)
	grantAddrStr := wallet.Address(grantAddr)
	accounts := fakeAccounts(t, map[string][]byte{
		sessAddrStr:  encodeSession(sessionKey, owner, 1),
		grantAddrStr: encodeGrant(sessAddr, viewer, wallet.CapWrite, 0, 1),
	})

	var refreshes int32
	fake := newFakeWS()
	src, err := New(Options{
		ProgramID:    "TestProgram1111111111111111111111111111111",
		SessionKey:   sessionKey,
		PollInterval: time.Hour, // a refresh can only come from the push path
		WSEndpoint:   "wss://test",
		Now:          now,
		Call: func(_ context.Context, method string, _ []any) (json.RawMessage, error) {
			if method != "getProgramAccounts" {
				t.Errorf("unexpected rpc method %q", method)
			}
			atomic.AddInt32(&refreshes, 1)
			return accounts, nil
		},
		dialWS: func(context.Context, string) (wsConn, error) { return fake, nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	src.reconcileInterval = 10 * time.Millisecond // re-subscribe promptly after the first refresh

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go src.Run(ctx, nil)

	// The watcher subscribes to the session account and the grant account.
	got := map[string]bool{}
	deadline := time.After(2 * time.Second)
	for len(got) < 2 {
		select {
		case a := <-fake.subs:
			got[a] = true
		case <-deadline:
			t.Fatalf("accountSubscribe not established; got %v", got)
		}
	}
	if !got[sessAddrStr] || !got[grantAddrStr] {
		t.Errorf("subscribed to %v, want session %s + grant %s", got, sessAddrStr, grantAddrStr)
	}

	// A notification drives an immediate refresh, well under the 1h poll.
	before := atomic.LoadInt32(&refreshes)
	fake.notify <- struct{}{}
	pushed := false
	for i := 0; i < 200 && !pushed; i++ {
		if atomic.LoadInt32(&refreshes) > before {
			pushed = true
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !pushed {
		t.Fatal("accountNotification did not trigger a refresh within 1s")
	}
}

func TestDeriveWSEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://api.devnet.solana.com": "wss://api.devnet.solana.com",
		"http://127.0.0.1:8899":         "ws://127.0.0.1:8899",
		"wss://already.ws":              "", // not http(s) → caller must set WSEndpoint
	}
	for in, want := range cases {
		if got := deriveWSEndpoint(in); got != want {
			t.Errorf("deriveWSEndpoint(%q) = %q, want %q", in, got, want)
		}
	}
}
