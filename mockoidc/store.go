package mockoidc

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"time"

	"github.com/bluele/gcache"
	"github.com/oklog/ulid/v2"
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

func (s *TokenStore) GetToken(sub string) (*Token, error) {
	val, err := s.backend.Get(sub)
	if errors.Is(err, gcache.KeyNotFoundError) {
		return nil, ErrNotFound
	}
	return val.(*Token), nil
}

func (s *TokenStore) AddToken(t *Token) error {
	return s.backend.Set(t.Sub, t)
}

func (s *TokenStore) RemoveToken(t *Token) {
	s.backend.Remove(t.Sub)
}

func (s *TokenStore) Purge() {
	s.backend.Purge()
}

func (s *TokenStore) ExposeToken(t *Token) (*Token, error) {
	t.AccessToken = ulid.Make().String()
	t.Iat = time.Now().Unix()
	return t, s.AddToken(t)
}

func (s *TokenStore) NewToken(sessionID string, clientID string, redirectURI string) *Token {
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
		Sub:         sub,
		Exp:         time.Now().Add(s.expiresIn).Unix(),
		Code:        ulid.Make().String(),
		AccessToken: "",
	}
}

func (s *TokenStore) getAll() []*Token {
	tokens := []*Token{}
	for _, v := range s.backend.GetALL(true) {
		tokens = append(tokens, v.(*Token))
	}
	return tokens
}

func (s *TokenStore) GetTokenByCode(code string, clientID string, redirectURI string) (*Token, error) {
	for _, token := range s.getAll() {
		if token.Code == code && token.Aud == clientID && token.RedirectURI == redirectURI {
			return token, nil
		}
	}
	return nil, ErrNotFound
}

func (s *TokenStore) GetTokenByAccessToken(accessToken string) (*Token, error) {
	for _, token := range s.getAll() {
		if token.AccessToken == accessToken {
			return token, nil
		}
	}
	return nil, ErrNotFound
}

func (s *TokenStore) GetTokenBySession(sessionID string, clientID string, redirectURI string) (*Token, error) {
	tokens := []*Token{}
	for _, token := range s.getAll() {
		if token.SessionID == sessionID && token.Aud == clientID && token.RedirectURI == redirectURI {
			tokens = append(tokens, token)
		}
	}
	if len(tokens) == 0 {
		return nil, ErrNotFound
	}
	sort.Sort(ByExpToken(tokens))
	return tokens[len(tokens)-1], ErrNotFound
}
