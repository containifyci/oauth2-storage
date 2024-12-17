package config

import (
	"time"

	"github.com/rs/zerolog/log"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type (
	Config struct {
		StorageFile     string
		PublicKey       string
		GRPCPort        int
		HTTPPort        int
		PodNamespace    string
		TokenSyncPeriod string
	}

	GithubOAuthConfig struct {
		ClientID     string   `yaml:"client_id" json:"clientId" envconfig:"CLIENT_ID"`
		ClientSecret string   `yaml:"client_secret" json:"clientSecret" envconfig:"CLIENT_SECRET"`
		Scopes       []string `yaml:"scopes" json:"scopes" envconfig:"SCOPES"`
		RedirectURL  string   `yaml:"redirect_url" json:"redirectUrl" envconfig:"REDIRECT_URL"`
	}
)

func (cfg Config) TokenSyncPeriodDuration() time.Duration {
	if cfg.TokenSyncPeriod == "" {
		return 60 * time.Minute
	}
	duration, err := time.ParseDuration(cfg.TokenSyncPeriod)
	if err != nil {
		log.Error().Err(err).Msgf("error %s parsing client timeout '%s'", err, cfg.TokenSyncPeriod)
		duration = 5 * time.Second
	}
	return duration
}

func (cfg *GithubOAuthConfig) GetConfig() *oauth2.Config {
	return &oauth2.Config{
		RedirectURL:  cfg.RedirectURL,
		ClientSecret: cfg.ClientSecret,
		ClientID:     cfg.ClientID,
		Scopes:       cfg.Scopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:       github.Endpoint.AuthURL,
			TokenURL:      github.Endpoint.TokenURL,
			DeviceAuthURL: github.Endpoint.DeviceAuthURL,
		},
	}
}
