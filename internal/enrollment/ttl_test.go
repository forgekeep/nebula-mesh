package enrollment

import (
	"context"
	"errors"
	"testing"
	"time"
)

type fakeGetter struct {
	val string
	err error
}

func (f fakeGetter) GetNetworkConfig(_ context.Context, _, _ string) (string, error) {
	return f.val, f.err
}

func TestTokenTTL(t *testing.T) {
	ctx := context.Background()
	tests := []struct {
		name       string
		getter     fakeGetter
		defaultTTL time.Duration
		networkID  string
		want       time.Duration
	}{
		{
			name:       "per-network override wins",
			getter:     fakeGetter{val: "30m"},
			defaultTTL: 2 * time.Hour,
			networkID:  "net1",
			want:       30 * time.Minute,
		},
		{
			name:       "empty override falls back to server default",
			getter:     fakeGetter{val: ""},
			defaultTTL: 2 * time.Hour,
			networkID:  "net1",
			want:       2 * time.Hour,
		},
		{
			name:       "getter error falls back to server default",
			getter:     fakeGetter{err: errors.New("boom")},
			defaultTTL: 90 * time.Minute,
			networkID:  "net1",
			want:       90 * time.Minute,
		},
		{
			name:       "unparseable override falls back to server default",
			getter:     fakeGetter{val: "not-a-duration"},
			defaultTTL: 3 * time.Hour,
			networkID:  "net1",
			want:       3 * time.Hour,
		},
		{
			name:       "non-positive override falls back to server default",
			getter:     fakeGetter{val: "0s"},
			defaultTTL: 4 * time.Hour,
			networkID:  "net1",
			want:       4 * time.Hour,
		},
		{
			name:       "empty networkID skips lookup and uses default",
			getter:     fakeGetter{val: "30m"},
			defaultTTL: 5 * time.Hour,
			networkID:  "",
			want:       5 * time.Hour,
		},
		{
			name:       "no default falls back to DefaultTokenTTL",
			getter:     fakeGetter{val: ""},
			defaultTTL: 0,
			networkID:  "net1",
			want:       DefaultTokenTTL,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := TokenTTL(ctx, tc.getter, tc.defaultTTL, tc.networkID)
			if got != tc.want {
				t.Fatalf("TokenTTL = %s, want %s", got, tc.want)
			}
		})
	}
}
