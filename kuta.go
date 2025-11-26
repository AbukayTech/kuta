package kuta

import (
	"time"

	"github.com/lborres/kuta/core"
	"github.com/lborres/kuta/crypto"
)

// Re-exports
type (
	SessionConfig = core.SessionConfig
	Session       = core.Session
	User          = core.User
	Account       = core.Account
)

const (
	defaultBasePath = "/api/auth"
)

type HTTPAdapter interface {
	RegisterRoutes(k *Kuta) error
}

type Config struct {
	Secret string

	Database core.AuthStorage

	HTTP HTTPAdapter

	// Optional config

	CacheAdapter   core.Cache
	SessionConfig  *SessionConfig
	PasswordHasher crypto.PasswordHandler
	BasePath       string
}

type Kuta struct {
	SessionManager *core.SessionManager
	PasswordHasher crypto.PasswordHandler
	Secret         string
	BasePath       string
}

func New(config Config) (*Kuta, error) {
	if config.Secret == "" {
		return nil, core.ErrSecretRequired
	}

	if config.Database == nil {
		return nil, core.ErrDBAdapterRequired
	}
	if config.HTTP == nil {
		return nil, core.ErrHTTPAdapterRequired
	}

	// Set Defaults

	// TODO: user should be able to opt out of cache
	cacheAdapter := config.CacheAdapter
	if cacheAdapter == nil {
		cacheAdapter = core.NewInMemoryCache(core.CacheConfig{
			TTL:     5 * time.Minute,
			MaxSize: 500,
		})
	}

	sessionConfig := config.SessionConfig
	if sessionConfig == nil {
		sessionConfig = &SessionConfig{
			MaxAge: 24 * time.Hour,
		}
	}

	passwordHasher := config.PasswordHasher
	if passwordHasher == nil {
		passwordHasher = crypto.NewArgon2()
	}

	basePath := config.BasePath
	if basePath == "" {
		basePath = defaultBasePath
	}

	sessionManager := core.NewSessionManager(
		*sessionConfig,
		config.Database,
		cacheAdapter,
	)

	kuta := &Kuta{
		SessionManager: sessionManager,
		PasswordHasher: passwordHasher,
		Secret:         config.Secret,
		BasePath:       basePath,
	}

	if err := config.HTTP.RegisterRoutes(kuta); err != nil {
		return nil, err
	}

	return kuta, nil
}
