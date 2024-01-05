package mockoidc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/bluele/gcache"
)

type TokenStore struct {
	backend   gcache.Cache
	expiresIn time.Duration
}

func NewTokenStore(size int, expiresIn time.Duration) (*TokenStore, error) {
	backend := gcache.New(size).LRU().Expiration(expiresIn).Build()
	return &TokenStore{
		backend:   backend,
		expiresIn: expiresIn,
	}, nil
}

func (s *TokenStore) GetToken(code string) (*Token, error) {
	val, err := s.backend.Get(code)
	if errors.Is(err, gcache.KeyNotFoundError) {
		return nil, ErrNotFound
	}
	return val.(*Token), nil
}

func (s *TokenStore) AddToken(t *Token) error {
	return s.backend.Set(t.Sub, t)
}

func (s *TokenStore) Purge() {
	s.backend.Purge()
}

func (s *TokenStore) NewToken(sessionID string, clientID string, redirectURI string, state string) *Token {
	hash := sha256.New()
	hash.Write([]byte(sessionID))
	hash.Write([]byte{':'})
	hash.Write([]byte(clientID))
	hash.Write([]byte{':'})
	hash.Write([]byte(redirectURI))
	sub := hex.EncodeToString(hash.Sum(nil))
	return &Token{
		SessionID:   sessionID,
		Aud:         clientID,
		AuthTime:    time.Now().Unix(),
		RedirectURI: redirectURI,
		State:       state,
		Sub:         sub,
		Exp:         time.Now().Add(s.expiresIn).Unix(),
	}
}

func (s *TokenStore) getAll() []*Token {
	tokens := []*Token{}
	for _, v := range s.backend.GetALL(true) {
		tokens = append(tokens, v.(*Token))
	}
	return tokens
}

func (s *TokenStore) GetTokenByTokenRequest(code string, clientID string, redirectURI string) (*Token, error) {
	token, err := s.GetToken(code)
	if err != nil {
		return nil, err
	}
	if token.Aud == clientID && token.RedirectURI == redirectURI {
		return token, nil
	}
	return nil, ErrNotFound
}

func (s *TokenStore) GetTokenBySessionRequest(sessionID string, clientID string, redirectURI string, state string) (*Token, error) {
	for _, token := range s.getAll() {
		if token.SessionID == sessionID && token.Aud == clientID && token.RedirectURI == redirectURI && token.State == state {
			return token, nil
		}
	}
	return nil, ErrNotFound
}
