package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenSyncPeriodDuration(t *testing.T) {
	tests := []struct {
		name   string
		period string
		want   time.Duration
	}{
		{
			name:   "empty",
			period: "",
			want:   60 * time.Minute,
		},
		{
			name:   "zero",
			period: "0m",
			want:   0 * time.Minute,
		},
		{
			name:   "1 minute",
			period: "1m",
			want:   1 * time.Minute,
		},
		{
			name:   "75 seconds",
			period: "75s",
			want:   75 * time.Second,
		},
		{
			name:   "3 days",
			period: "72h",
			want:   3 * 24 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := Config{
				TokenSyncPeriod: tt.period,
			}

			assert.Equal(t, tt.want, cfg.TokenSyncPeriodDuration())
		})
	}
}

func TestGetConfig(t *testing.T) {
	t.Parallel()

	cfg := GithubOAuthConfig{
		ClientID:     "client_id",
		ClientSecret: "client_secret",
		Scopes:       []string{"repo", "user"},
		RedirectURL:  "http://localhost:8080/oauth2/callback",
	}
	config := cfg.GetConfig()
	assert.Equal(t, "client_id", config.ClientID)
	assert.Equal(t, "client_secret", config.ClientSecret)
	assert.Equal(t, "http://localhost:8080/oauth2/callback", config.RedirectURL)
	assert.Equal(t, []string{"repo", "user"}, config.Scopes)
}
