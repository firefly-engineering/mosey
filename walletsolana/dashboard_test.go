package walletsolana

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/firefly-engineering/mosey/wallet"
)

func TestSessionsByOwner(t *testing.T) {
	owner := key(t)
	s1, s2 := key(t), key(t)

	// The RPC is asked to filter by owner; the fake returns the already
	// filtered set (two sessions owned by `owner`).
	accounts := fakeAccounts(t, map[string][]byte{
		wallet.Address(key(t)): encodeSession(s1, owner, 1),
		wallet.Address(key(t)): encodeSession(s2, owner, 7),
	})

	var sawMemcmp bool
	src, err := New(Options{
		ProgramID:  "TestProgram1111111111111111111111111111111",
		SessionKey: key(t),
		Now:        func() time.Time { return time.Unix(2_000_000, 0) },
		call: func(_ context.Context, method string, params []any) (json.RawMessage, error) {
			if method != "getProgramAccounts" {
				t.Fatalf("unexpected rpc method %q", method)
			}
			// The second param should carry a memcmp filter at the owner offset.
			if len(params) >= 2 {
				if cfg, ok := params[1].(map[string]any); ok {
					if _, ok := cfg["filters"]; ok {
						sawMemcmp = true
					}
				}
			}
			return accounts, nil
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got, err := src.SessionsByOwner(context.Background(), owner)
	if err != nil {
		t.Fatalf("SessionsByOwner: %v", err)
	}
	if !sawMemcmp {
		t.Error("SessionsByOwner did not pass a filters option to getProgramAccounts")
	}
	if len(got) != 2 {
		t.Fatalf("got %d sessions, want 2", len(got))
	}
	want := map[string]uint16{wallet.Address(s1): 1, wallet.Address(s2): 7}
	for _, os := range got {
		epoch, ok := want[wallet.Address(os.SessionKey)]
		if !ok {
			t.Errorf("unexpected session key %s", wallet.Address(os.SessionKey))
			continue
		}
		if os.Epoch != epoch {
			t.Errorf("session %s epoch = %d, want %d", wallet.Address(os.SessionKey), os.Epoch, epoch)
		}
		if os.Address == "" {
			t.Errorf("session %s has empty on-chain address", wallet.Address(os.SessionKey))
		}
	}
}
