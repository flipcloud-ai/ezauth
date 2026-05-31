package apis

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"

	"github.com/flipcloud-ai/ezauth/pkg/utils/encryption"
)

// Identity type constants define the subject type stored in the session profile.
const (
	UserIDType     = "user"
	GroupIDType    = "group"
	RoleIDType     = "role"
	OIDCUserIDType = "oauth"
)

const (
	codecVersionRaw      byte = 0x01 // uncompressed: [0x01][msgpack...]
	codecVersionLZ4Block byte = 0x03 // lz4 block: [0x03][origSize 4B BE][compressed...]; 0x02 is unassigned/reserved
	codecSmallPayload         = 256  // payloads below this size skip compression
)

// Session is the authenticated user session state stored in a cookie.
// @Description Authenticated user session containing identity profile, tokens, and expiration metadata.
type Session struct {
	CreatedAt int64 `msgpack:"ca,omitempty"`
	ExpiresOn int64 `msgpack:"eo,omitempty"`

	AccessToken  string `msgpack:"at,omitempty" json:"access_token"`
	IDToken      string `msgpack:"it,omitempty" json:"id_token,omitempty"`
	RefreshToken string `msgpack:"rt,omitempty" json:"refresh_token"`

	Nonce []byte `msgpack:"n,omitempty"`

	Profile
}

// Profile holds the identity claims from an IdP or database.
// @Description User identity profile fields including subject, email, groups, and provider metadata.
type Profile struct {
	Subject           string   `msgpack:"sub,omitempty" json:"sub,omitempty"`
	Email             string   `msgpack:"e,omitempty" json:"email"`
	EmailVerified     bool     `msgpack:"ev,omitempty" json:"email_verified,omitempty"`
	User              string   `msgpack:"u,omitempty" json:"name"`
	Groups            []string `msgpack:"g,omitempty" json:"groups"`
	PreferredUsername string   `msgpack:"pu,omitempty" json:"preferred_username"`
	IDType            string   `msgpack:"idtyp,omitempty" json:"idtyp,omitempty"`
	FirstName         string   `msgpack:"fn,omitempty" json:"first_name"`
	LastName          string   `msgpack:"ln,omitempty" json:"last_name"`
	// Provider is the name of the identity provider that minted this
	// session. Set on OIDC callback so logout / revocation can address the
	// correct IdP without trusting a client-supplied query parameter.
	Provider string `msgpack:"pr,omitempty" json:"provider,omitempty"`
}

// CreatedAtNow sets a SessionState's CreatedAt to now
func (s *Session) CreatedAtNow() {
	s.CreatedAt = time.Now().Unix()
}

// ExpiresIn sets an expiration a certain duration from CreatedAt.
// CreatedAt will be set to time.Now if it is unset.
func (s *Session) ExpiresIn(d time.Duration) {
	if s.CreatedAt == 0 {
		s.CreatedAtNow()
	}
	s.ExpiresOn = s.CreatedAt + int64(d/time.Second)
}

// IsExpired checks whether the session has expired
func (s *Session) IsExpired() bool {
	if s.ExpiresOn != 0 && s.ExpiresOn < time.Now().Unix() {
		return true
	}
	return false
}

// Age returns the age of a session
func (s *Session) Age() time.Duration {
	if s.CreatedAt != 0 {
		return time.Now().Truncate(time.Second).Sub(time.Unix(s.CreatedAt, 0))
	}
	return 0
}

// CheckNonce compares the Nonce against a potential hash of it
func (s *Session) CheckNonce(hashed string) bool {
	return encryption.CheckNonce(s.Nonce, hashed)
}

// EncodeSessionState returns an encrypted, optionally lz4 compressed, MessagePack encoded session
func (s *Session) EncodeSessionState(c encryption.Cipher, compress bool) ([]byte, error) {
	packed, err := msgpack.Marshal(s)
	if err != nil {
		return nil, fmt.Errorf("error marshalling session state to msgpack: %w", err)
	}

	var out []byte
	if compress && len(packed) >= codecSmallPayload {
		out, err = lz4CompressBlock(packed)
		if err != nil {
			return nil, err
		}
	} else {
		out = make([]byte, 1+len(packed))
		out[0] = codecVersionRaw
		copy(out[1:], packed)
	}
	return c.Encrypt(out)
}

// DecodeSessionState decodes a LZ4 compressed MessagePack into a Session State.
// The compressed parameter is vestigial: format is now self-describing via the version byte prefix.
func DecodeSessionState(data []byte, c encryption.Cipher, compressed bool) (*Session, error) {
	decrypted, err := c.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("error decrypting the session state: %w", err)
	}

	if len(decrypted) == 0 {
		return nil, fmt.Errorf("error decrypting the session state: empty payload")
	}

	var packed []byte
	switch decrypted[0] {
	case codecVersionRaw:
		packed = decrypted[1:]
	case codecVersionLZ4Block:
		packed, err = lz4DecompressBlock(decrypted)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("error decoding session state: unknown codec version 0x%02x", decrypted[0])
	}

	var ss Session
	err = msgpack.Unmarshal(packed, &ss)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling data to session state: %w", err)
	}

	return &ss, nil
}

func lz4CompressBlock(payload []byte) ([]byte, error) {
	bound := lz4.CompressBlockBound(len(payload))
	buf := make([]byte, 5+bound)
	buf[0] = codecVersionLZ4Block
	binary.BigEndian.PutUint32(buf[1:5], uint32(len(payload))) //nolint:gosec // session payloads are always well within uint32 range
	n, err := lz4.CompressBlock(payload, buf[5:], nil)
	if err != nil {
		return nil, fmt.Errorf("lz4 compress block: %w", err)
	}
	return buf[:5+n], nil
}

func lz4DecompressBlock(data []byte) ([]byte, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("lz4 block: data too short")
	}
	origSize := binary.BigEndian.Uint32(data[1:5])
	out := make([]byte, origSize)
	n, err := lz4.UncompressBlock(data[5:], out)
	if err != nil {
		return nil, fmt.Errorf("lz4 decompress block: %w", err)
	}
	if n != int(origSize) { //nolint:gosec // origSize fits int: checked at compress time (<=math.MaxUint32) and session payloads are small
		return nil, fmt.Errorf("lz4 decompress block: size mismatch (got %d, want %d)", n, origSize)
	}
	return out, nil
}
