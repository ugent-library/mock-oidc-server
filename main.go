package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/bluele/gcache"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/oklog/ulid/v2"
	"github.com/ory/graceful"
	"github.com/spf13/cobra"
	"github.com/ugent-library/zaphttp"
	"github.com/ugent-library/zaphttp/zapchi"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2"
)

var logger *zap.SugaredLogger
var sessionStore *sessions.CookieStore
var endpoints *providerEndpoints

const sessionName = "MOCK_OIDC_SERVER_SESSION"

var expiresIn = time.Hour
var logins = gcache.New(100).LRU().Expiration(expiresIn).Build()
var keyID = ""
var rsaProc *rsaProcessor

func initLogger() {
	l, e := zap.NewDevelopment()
	cobra.CheckErr(e)
	logger = l.Sugar()
}

func initRSA(publicKeyPath string, privateKeyPath string) {
	keyID = ulid.Make().String()
	r, err := newRSAProcessor(publicKeyPath, privateKeyPath)
	if err != nil {
		panic(err)
	}
	rsaProc = r
}

func initSessionStore(sessionSecret string) {
	sessionStore = sessions.NewCookieStore([]byte(sessionSecret))
	sessionStore.MaxAge(int(expiresIn))
	sessionStore.Options.Path = "/auth"
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = false
}

func initEndpoints(uriBase string) {
	endpoints = &providerEndpoints{
		Issuer:                uriBase,
		AuthorizationEndpoint: uriBase + "/auth",
		TokenEndpoint:         uriBase + "/token",
		JWKSURI:               uriBase + "/certs",
		UserInfoEndpoint:      uriBase + "/userinfo",
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_post",
		},
		GrantTypesSupported: []string{
			"authorization_code",
		},
		ResponseTypesSupported:   []string{"code"},
		ClaimsParameterSupported: false,
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
		ClaimsSupported: []string{
			"aud",
			"sub",
			"iss",
			"auth_time",
			"name",
			"given_name",
			"family_name",
			"preferred_username",
			"email",
		},
		ClaimTypesSupported:              []string{"normal"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}
}

func sendOIDCError(w http.ResponseWriter, statusCode int, err string, err_desc string) {
	data, _ := json.Marshal(OIDCError{
		Error:            err,
		ErrorDescription: err_desc,
	})
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(data)
}

func AuthGet(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionName)

	params := r.URL.Query()
	responseType := params.Get("response_type")
	state := params.Get("state")
	redirectURI := params.Get("redirect_uri")
	scope := params.Get("scope")
	clientID := params.Get("client_id")

	redirectTo, err := url.ParseRequestURI(redirectURI)
	if err != nil {
		http.Error(w, "unable to parse parameter redirect_uri", http.StatusBadRequest)
		return
	}

	if oldCode, ok := session.Values["code"]; ok {
		q := redirectTo.Query()
		if state != "" {
			q.Set("state", state)
		}
		q.Set("code", oldCode.(string))
		q.Set("iss", endpoints.Issuer)
		redirectTo.RawQuery = q.Encode()
		http.Redirect(w, r, redirectTo.String(), http.StatusFound)
		return
	}

	var oidcError *OIDCError

	if responseType != "code" {
		oidcError = &OIDCError{Error: "unsupported_response_type", ErrorDescription: "response_type must be code"}
	} else if GetClient(clientID) == nil {
		oidcError = &OIDCError{Error: "unauthorized_client", ErrorDescription: "unknown client_id"}
	} else {
		requestedScopes := strings.Split(scope, " ")
		for i := 0; i < len(requestedScopes); i++ {
			requestedScopes[i] = strings.TrimSpace(requestedScopes[i])
		}
		for _, rs := range requestedScopes {
			if !slices.Contains(endpoints.ScopesSupported, rs) {
				oidcError = &OIDCError{
					Error:            "invalid_scope",
					ErrorDescription: "invalid scope " + rs,
				}
				break
			}
		}
	}

	if oidcError != nil {
		q := redirectTo.Query()
		q.Set("error", oidcError.Error)
		q.Set("error_description", oidcError.ErrorDescription)
		redirectTo.RawQuery = q.Encode()
		http.Redirect(w, r, redirectTo.String(), http.StatusFound)
		return
	}

	templateAuth.Execute(w, templateAuthParams{
		FormAction:   "/auth",
		Scope:        scope,
		RedirectURI:  redirectURI,
		State:        state,
		ClientID:     clientID,
		ResponseType: responseType,
	})
}

func AuthPost(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionName)
	r.ParseForm()

	params := r.PostForm

	username := params.Get("username")
	responseType := params.Get("response_type")
	state := params.Get("state")
	redirectURI := params.Get("redirect_uri")
	scope := params.Get("scope")
	clientID := params.Get("client_id")

	redirectTo, err := url.ParseRequestURI(redirectURI)
	if err != nil {
		http.Error(w, "unable to parse parameter redirect_uri", http.StatusBadRequest)
		return
	}

	var oidcError *OIDCError

	if responseType != "code" {
		oidcError = &OIDCError{Error: "unsupported_response_type", ErrorDescription: "response_type must be code"}
	} else if GetClient(clientID) == nil {
		oidcError = &OIDCError{Error: "unauthorized_client", ErrorDescription: "unknown client_id"}
	} else {
		requestedScopes := strings.Split(scope, " ")
		for i := 0; i < len(requestedScopes); i++ {
			requestedScopes[i] = strings.TrimSpace(requestedScopes[i])
		}
		for _, rs := range requestedScopes {
			if !slices.Contains(endpoints.ScopesSupported, rs) {
				oidcError = &OIDCError{
					Error:            "invalid_scope",
					ErrorDescription: "invalid scope " + rs,
				}
				break
			}
		}
	}

	if oidcError != nil {
		q := redirectTo.Query()
		q.Set("error", oidcError.Error)
		q.Set("error_description", oidcError.ErrorDescription)
		redirectTo.RawQuery = q.Encode()
		http.Redirect(w, r, redirectTo.String(), http.StatusFound)
		return
	}

	var authError string

	if username != "" {
		var user *User = GetUser(username)
		if user == nil {
			authError = "Unable to find user " + username
		} else {
			code := ulid.Make().String()
			session.Values["code"] = code
			if err := sessionStore.Save(r, w, session); err != nil {
				logger.Errorf("unable to save session: %s", err)
				http.Error(w, "unexpected error", http.StatusInternalServerError)
				return
			}
			now := time.Now()
			newLogin := &Login{
				Aud:         clientID,
				Sub:         ulid.Make().String(),
				RedirectURI: redirectURI,
				User:        user,
				AuthTime:    &now,
				State:       state,
			}
			if err := logins.Set(code, newLogin); err != nil {
				logger.Errorf("unable to store mapping code to user: %s", err)
				http.Error(w, "unexpected error", http.StatusInternalServerError)
				return
			}
			q := redirectTo.Query()
			if state != "" {
				q.Set("state", state)
			}
			q.Set("iss", endpoints.Issuer)
			q.Set("code", code)
			redirectTo.RawQuery = q.Encode()
			http.Redirect(w, r, redirectTo.String(), http.StatusFound)
			return
		}
	}

	templateAuth.Execute(w, templateAuthParams{
		FormAction:   "/auth",
		Error:        authError,
		Scope:        scope,
		RedirectURI:  redirectURI,
		State:        state,
		ClientID:     clientID,
		ResponseType: responseType,
	})
}

func loginToClaims(login *Login) jwt.MapClaims {
	claims := jwt.MapClaims{}
	for _, c := range login.User.Claims {
		claims[c.Name] = c.Value
	}
	claims["iss"] = endpoints.Issuer
	claims["sub"] = login.Sub
	claims["aud"] = login.Aud
	claims["auth_time"] = login.AuthTime.Unix()
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(expiresIn).Unix()
	return claims
}

func Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		sendOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid_request")
		return
	}

	params := r.PostForm

	redirectURI := params.Get("redirect_uri")
	code := params.Get("code")
	grantType := params.Get("grant_type")
	clientID := params.Get("client_id")
	clientSecret := params.Get("client_secret")

	if redirectURI == "" || code == "" || grantType != "authorization_code" || clientID == "" || clientSecret == "" {
		sendOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid_request")
		return
	}

	client := GetClient(clientID)
	if client == nil || client.Secret != clientSecret {
		sendOIDCError(w, http.StatusUnauthorized, "invalid_client", "invalid_client")
		return
	}

	l, err := logins.Get(code)
	if errors.Is(err, gcache.KeyNotFoundError) {
		sendOIDCError(w, http.StatusBadRequest, "invalid_grant", "invalid_grant")
		return
	} else if err != nil {
		logger.Errorf("unable to fetch login from store: %s", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	login := l.(*Login)
	if login.RedirectURI != redirectURI {
		sendOIDCError(w, http.StatusBadRequest, "invalid_grant", "invalid_grant")
		return
	}

	//ALL OK
	claims := loginToClaims(login)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// NOTE: This is important as the library matches this keyID with the public key
	token.Header["kid"] = keyID
	idToken, err := token.SignedString(rsaProc.signKey)
	if err != nil {
		logger.Errorf("unable to sign jwt token: %s", err)
		sendOIDCError(w, http.StatusInternalServerError, "server_errror", "server_error")
		return
	}
	t := &tokens{
		TokenType:   "Bearer",
		IDToken:     idToken,
		AccessToken: code,
		ExpiresIn:   int(expiresIn.Seconds()),
	}
	data, _ := json.Marshal(t)
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func UserInfo(w http.ResponseWriter, r *http.Request) {
	accessToken := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))

	var statusCode int
	var data []byte = []byte{}

	if accessToken == "" {
		statusCode = http.StatusUnauthorized
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("WWW-Authenticate", "Bearer")
		data = []byte("unauthorized")
	} else if l, err := logins.Get(accessToken); err != nil {
		if errors.Is(err, gcache.KeyNotFoundError) {
			statusCode = http.StatusUnauthorized
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("WWW-Authenticate", "Bearer error=\"unsufficient_scope\"")
			data = []byte("unauthorized")
		} else {
			statusCode = http.StatusInternalServerError
			w.Header().Set("Content-Type", "text/plain")
			data = []byte("internal_server_error")
		}
	} else {
		statusCode = http.StatusOK
		w.Header().Add("Content-Type", "application/json")
		login := l.(*Login)
		data, _ = json.Marshal(login.User.Claims)
	}

	w.WriteHeader(statusCode)
	w.Write(data)
}

func Certs(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       rsaProc.verifyKey,
		KeyID:     keyID,
		Use:       "sig",
		Algorithm: "RS256",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}
	data, _ := json.Marshal(jwks)

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func Discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	data, _ := json.Marshal(endpoints)
	w.Write(data)
}

func Clear(w http.ResponseWriter, r *http.Request) {
	logins.Purge()
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	initLogger()
	initSessionStore("ABCDEFGH")
	initRSA(".data/oidc.rsa.pub", ".data/oidc.rsa")
	initEndpoints("http://localhost:3000")

	mux := chi.NewMux()
	mux.Use(middleware.RequestID)
	mux.Use(middleware.RealIP)
	mux.Use(zaphttp.SetLogger(logger.Desugar(), zapchi.RequestID))
	mux.Use(middleware.RequestLogger(zapchi.LogFormatter()))
	mux.Use(middleware.Recoverer)

	mux.Get("/.well-known/openid-configuration", Discovery)
	mux.Get("/auth", AuthGet)
	mux.Post("/auth", AuthPost)
	mux.Post("/token", Token)
	mux.Get("/certs", Certs)
	mux.Get("/clear", Clear)

	srv := graceful.WithDefaults(&http.Server{
		Addr:         ":3000",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	})
	if err := graceful.Graceful(srv.ListenAndServe, srv.Shutdown); err != nil {
		panic(err)
	}
	logger.Info("gracefully stopped server")
}
