package auth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/flipcloud-ai/ezauth/config"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezutils "github.com/flipcloud-ai/ezauth/pkg/utils"
)

// JWT default claim values.
// These domains do not exist — they are placeholder identifiers only.
// Set jwt.token_issuer and jwt.audience in your application config to override them.
const (
	DefaultTokenIssuer = "auth.ezauth.com" //nolint:gosec // not a credential
	DefaultAudience    = "sts.ezauth.com"
)

// AuthClaim extends jwt.RegisteredClaims with ezauth-specific identity fields.
//
//nolint:revive // established API name; renaming would be a breaking change
type AuthClaim struct {
	Email             string   `msgpack:"e,omitempty" json:"email"`
	EmailVerified     bool     `msgpack:"ev,omitempty" json:"email_verified,omitempty"`
	User              string   `msgpack:"u,omitempty" json:"name"`
	Groups            []string `msgpack:"g,omitempty" json:"groups"`
	PreferredUsername string   `msgpack:"pu,omitempty" json:"preferred_username"`
	jwt.RegisteredClaims
}

func getSignMethod(opts config.JWTConfig) jwt.SigningMethod {
	switch opts.SigningMethod {
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "ES256":
		return jwt.SigningMethodES256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	case "HS384":
		return jwt.SigningMethodHS384
	case "HS512":
		return jwt.SigningMethodHS512
	default:
		return jwt.SigningMethodHS256
	}
}

func getSecretKey(opts config.JWTConfig) ([]byte, error) {
	secret := opts.SecretKey.Bytes()
	if len(secret) == 0 {
		return nil, fmt.Errorf("jwt secret_key is required")
	}
	signMethod := getSignMethod(opts)
	if _, ok := signMethod.(*jwt.SigningMethodHMAC); ok {
		if len(secret) < 32 {
			return nil, fmt.Errorf("HMAC signing requires secret_key >= 32 bytes, got %d", len(secret))
		}
	}
	return secret, nil
}

func getIssuer(opts config.JWTConfig) string {
	issuer := opts.TokenIssuer
	if issuer == "" {
		issuer = DefaultTokenIssuer
	}
	return issuer
}

func getAudience(opts config.JWTConfig) string {
	audience := opts.Audience
	if audience == "" {
		audience = DefaultAudience
	}
	return audience
}

// GenerateToken creates a signed JWT token for the given profile using the provided JWT config.
func GenerateToken(opts config.JWTConfig, profile ezapi.Profile) (string, error) {
	issuer := getIssuer(opts)
	audience := getAudience(opts)
	uuid, err := ezutils.NewRandomUUID()
	if err != nil {
		return "", err
	}
	claims := &AuthClaim{
		Email:             profile.Email,
		EmailVerified:     profile.EmailVerified,
		User:              profile.User,
		Groups:            profile.Groups,
		PreferredUsername: profile.PreferredUsername,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(opts.ExpireDuration)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			Issuer:    issuer,
			Subject:   profile.Subject,
			ID:        uuid,
			Audience:  []string{audience},
		},
	}

	var signKey interface{}
	signMethod := getSignMethod(opts)
	keyPath := opts.KeyPath
	if _, ok := signMethod.(*jwt.SigningMethodHMAC); ok {
		secret, err := getSecretKey(opts)
		if err != nil {
			return "", err
		}
		signKey = secret
	} else if _, ok := signMethod.(*jwt.SigningMethodRSA); ok {
		signKey, err = ezutils.LoadRSAPrivateKeyFromFile(keyPath + "/private_key.pem")
	} else if _, ok := signMethod.(*jwt.SigningMethodECDSA); ok {
		signKey, err = ezutils.LoadECDSAPrivateKeyFromFile(keyPath + "/private_key.pem")
	} else {
		err = fmt.Errorf("unexpected signing method: %v", opts.SigningMethod)
	}
	if err != nil {
		return "", err
	}
	// Create a new token object, specifying signing method and the claims
	token := jwt.NewWithClaims(signMethod, claims)
	// Sign and get the complete encoded token as a string using the secret
	tokenString, err := token.SignedString(signKey)
	if err != nil {
		return "", fmt.Errorf("sign token: %w", err)
	}
	return tokenString, nil
}

// ParseToken validates and parses a JWT token string using the provided JWT config.
func ParseToken(opts config.JWTConfig, tokenString string) (*AuthClaim, error) {
	token, err := jwt.ParseWithClaims(tokenString, &AuthClaim{}, func(token *jwt.Token) (interface{}, error) {
		var parseKey interface{}
		var err error
		keyPath := opts.KeyPath
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); ok {
			secret, secretErr := getSecretKey(opts)
			if secretErr != nil {
				return nil, secretErr
			}
			parseKey = secret
		} else if _, ok := token.Method.(*jwt.SigningMethodRSA); ok {
			parseKey, err = ezutils.LoadRSAPublicKeyFromFile(keyPath + "/public_key.pem")
		} else if _, ok := token.Method.(*jwt.SigningMethodECDSA); ok {
			parseKey, err = ezutils.LoadECDSAPublicKeyFromFile(keyPath + "/public_key.pem")
		} else {
			err = fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		if err != nil {
			return nil, err
		}
		// parseKey is a []byte containing your secret, e.g. []byte("my_secret_key")
		return parseKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}
	if claims, ok := token.Claims.(*AuthClaim); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token claims")
}
