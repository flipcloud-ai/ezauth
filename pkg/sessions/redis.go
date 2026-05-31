package sessions

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	"github.com/flipcloud-ai/ezauth/pkg/utils/encryption"
)

// RedisStore implements SessionStore by persisting session data in Redis.
type RedisStore struct {
	store
	client      redis.Cmdable
	redisConfig *config.RedisConfig
	cipher      encryption.Cipher
}

// NewRedisStore creates a RedisStore using the given cookie and Redis configuration.
func NewRedisStore(cookieOpts *config.CookieStoreOptions, redisConfig *config.RedisConfig, refreshPeriod time.Duration) (SessionStore, error) {
	if redisConfig.Addr == "" {
		return nil, fmt.Errorf("redis addr is required for Redis session store")
	}
	if redisConfig.TTL <= 0 {
		return nil, fmt.Errorf("redis TTL must be greater than 0 for Redis session store")
	}

	client := redis.NewClient(&redis.Options{
		Addr:     redisConfig.Addr,
		Password: redisConfig.Password,
		DB:       redisConfig.DB,
	})

	if ParseSameSite(cookieOpts.SameSite) == http.SameSiteNoneMode && !cookieOpts.Secure {
		return nil, fmt.Errorf("cookie with SameSite=None must be Secure, or use a different SameSite value")
	}

	var encCipher encryption.Cipher
	if !redisConfig.EncryptSecret.IsZero() {
		var err error
		encCipher, err = encryption.NewGCMCipher(redisConfig.EncryptSecret.Bytes())
		if err != nil {
			return nil, fmt.Errorf("error initialising encrypt cipher for Redis session store: %w", err)
		}
	}

	return &RedisStore{
		store: store{
			RefreshPeriod: refreshPeriod,
			Cookie:        cookieOpts,
		},
		client:      client,
		redisConfig: redisConfig,
		cipher:      encCipher,
	}, nil
}

func (s *RedisStore) sessionKey(sessionID string) string {
	return s.redisConfig.Prefix + "session:" + sessionID
}

func (s *RedisStore) redisTTL(session *ezapi.Session) time.Duration {
	if session.ExpiresOn != 0 {
		ttl := time.Until(time.Unix(session.ExpiresOn, 0))
		if ttl > 0 {
			return ttl
		}
	}
	return s.redisConfig.TTL
}

// Save stores the session in Redis and sets a signed session-ID cookie.
// When an existing valid session cookie is present, Save reuses its session ID
// so that refreshes update the same Redis key rather than leaking orphaned keys.
func (s *RedisStore) Save(rw http.ResponseWriter, req *http.Request, session *ezapi.Session) error {
	if session.CreatedAt == 0 {
		session.CreatedAtNow()
	}

	var rawID []byte
	existing, err := s.getRawSessionID(req)
	if err == nil {
		rawID = existing
	} else {
		rawID = make([]byte, 32)
		if _, rerr := rand.Read(rawID); rerr != nil {
			return fmt.Errorf("error generating session ID: %w", rerr)
		}
	}
	encodedID := base64.RawURLEncoding.EncodeToString(rawID)

	data, err := msgpack.Marshal(session)
	if err != nil {
		return fmt.Errorf("error marshalling session: %w", err)
	}

	if s.cipher != nil {
		data, err = s.cipher.Encrypt(data)
		if err != nil {
			return fmt.Errorf("error encrypting session: %w", err)
		}
	}

	ttl := s.redisTTL(session)
	if err := s.client.Set(req.Context(), s.sessionKey(encodedID), data, ttl).Err(); err != nil {
		return fmt.Errorf("error saving session to redis: %w", err)
	}

	signed, err := encryption.SignedValue(s.Cookie.Secret.Bytes(), s.Cookie.Name, rawID)
	if err != nil {
		return err
	}
	c := MakeCookieFromOptions(req, signed, s.Cookie)
	http.SetCookie(rw, c)
	return nil
}

// Load reads the session-ID cookie, fetches session data from Redis, and
// unmarshals it. Returns ErrNeedsRefresh when the session age exceeds the
// configured refresh period or the session has expired.
func (s *RedisStore) Load(req *http.Request) (*ezapi.Session, error) {
	sessionID, err := s.getSessionID(req)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %w", ErrCorruptedSession, err)
	}

	data, err := s.client.Get(req.Context(), s.sessionKey(sessionID)).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, http.ErrNoCookie
		}
		return nil, fmt.Errorf("error loading session from redis: %w", err)
	}

	if s.cipher != nil {
		data, err = s.cipher.Decrypt(data)
		if err != nil {
			return nil, fmt.Errorf("%w: error decrypting session: %w", ErrCorruptedSession, err)
		}
	}

	var session ezapi.Session
	if err := msgpack.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("%w: error unmarshalling session: %w", ErrCorruptedSession, err)
	}

	if s.needsRefresh(&session) || session.IsExpired() {
		return &session, ErrNeedsRefresh
	}
	return &session, nil
}

// Clear deletes the session from Redis and emits a clearing cookie.
// The clearing cookie is the load-bearing operation — even if the Redis DEL
// fails, the browser will evict the session cookie, preventing subsequent
// requests from carrying a now-invalid session ID.
func (s *RedisStore) Clear(rw http.ResponseWriter, req *http.Request) error {
	sessionID, err := s.getSessionID(req)
	if err == nil {
		if delErr := s.client.Del(req.Context(), s.sessionKey(sessionID)).Err(); delErr != nil {
			ezlog.FromContext(req.Context()).Error("Error deleting session from Redis", ezlog.Err(delErr))
		}
	}

	clearCookie := MakeCookieFromOptions(req, "", s.Cookie) //nolint:gosec // Secure/HttpOnly/SameSite attributes are set by MakeCookieFromOptions from s.Cookie config
	clearCookie.MaxAge = -1
	if !clearCookie.Expires.IsZero() {
		clearCookie.Expires = time.Now()
	}
	http.SetCookie(rw, clearCookie)
	return nil
}

// VerifyConnection pings Redis to verify connectivity.
func (s *RedisStore) VerifyConnection(ctx context.Context) error {
	if err := s.client.Ping(ctx).Err(); err != nil {
		return fmt.Errorf("ping redis: %w", err)
	}
	return nil
}

// Close releases the Redis client connection pool.
func (s *RedisStore) Close() error {
	if cl, ok := s.client.(interface{ Close() error }); ok {
		return cl.Close()
	}
	return nil
}

// getSessionID reads and validates the session-ID cookie, returning the raw
// session ID bytes as a base64 string.
func (s *RedisStore) getSessionID(req *http.Request) (string, error) {
	c, err := req.Cookie(s.Cookie.Name)
	if err != nil {
		return "", fmt.Errorf("get session cookie: %w", err)
	}
	signedValue, err := encryption.Validate(c, s.Cookie.Secret.Bytes())
	if err != nil {
		return "", fmt.Errorf("session cookie validation failed: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(signedValue), nil
}

// getRawSessionID reads the session cookie and returns the raw validated bytes.
// Returns (nil, error) when no cookie is present or the cookie is tampered.
func (s *RedisStore) getRawSessionID(req *http.Request) ([]byte, error) {
	c, err := req.Cookie(s.Cookie.Name)
	if err != nil {
		return nil, fmt.Errorf("get session cookie: %w", err)
	}
	return encryption.Validate(c, s.Cookie.Secret.Bytes())
}
