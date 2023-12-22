package main

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v8"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ory/graceful"
	"github.com/spf13/cobra"
	"github.com/ugent-library/mock-oidc-server/mockoidc"
	"github.com/ugent-library/zaphttp"
	"github.com/ugent-library/zaphttp/zapchi"
	"go.uber.org/zap"

	_ "github.com/joho/godotenv/autoload"
)

var logger *zap.SugaredLogger
var config Config

func initLogger() {
	var l *zap.Logger
	var e error
	if config.Production {
		l, e = zap.NewProduction()
	} else {
		l, e = zap.NewDevelopment()
	}
	cobra.CheckErr(e)
	logger = l.Sugar()
}

func initConfig() {
	cobra.CheckErr(env.ParseWithOptions(&config, env.Options{
		Prefix: "MOCK_OIDC_",
	}))
}

func loadClients() ([]*mockoidc.Client, error) {
	var reader io.Reader
	var clients []*mockoidc.Client
	if config.Clients != "" {
		reader = strings.NewReader(config.Clients)
	} else if config.ClientsPath != "" {
		r, err := os.Open(config.ClientsPath)
		if err != nil {
			return nil, err
		}
		reader = r
	}
	dec := json.NewDecoder(reader)
	for {
		err := dec.Decode(&clients)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
	}
	return clients, nil
}

func loadUsers() ([]*mockoidc.User, error) {
	var reader io.Reader
	var users []*mockoidc.User
	if config.Users != "" {
		reader = strings.NewReader(config.Users)
	} else if config.UsersPath != "" {
		r, err := os.Open(config.UsersPath)
		if err != nil {
			return nil, err
		}
		reader = r
	}
	dec := json.NewDecoder(reader)
	for {
		err := dec.Decode(&users)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
	}
	return users, nil
}

func loadPublicKey() (*rsa.PublicKey, error) {
	if config.PublicKeyPath != "" {
		return loadRSAPublicKeyFromFile(config.PublicKeyPath)
	} else if config.PublicKey != "" {
		return parseRSAPublicKey([]byte(config.PublicKey))
	}
	return nil, errors.New("neither PUBLIC_KEY_PATH nor PUBLIC_KEY given")
}
func loadPrivateKey() (*rsa.PrivateKey, error) {
	if config.PrivateKeyPath != "" {
		return loadRSAPrivateKeyFromFile(config.PrivateKeyPath)
	} else if config.PrivateKey != "" {
		return parseRSAPrivateKey([]byte(config.PrivateKey))
	}
	return nil, errors.New("neither PRIVATE_KEY_PATH nor PRIVATE_KEY given")
}

func main() {
	initConfig()
	initLogger()

	clients, err := loadClients()
	if err != nil {
		panic(err)
	}

	users, err := loadUsers()
	if err != nil {
		panic(err)
	}

	publicKey, err := loadPublicKey()
	if err != nil {
		panic(err)
	}

	privateKey, err := loadPrivateKey()
	if err != nil {
		panic(err)
	}

	srvConfig := mockoidc.Config{
		SessionCookieName: config.SessionCookieName,
		SessionSecret:     config.SessionSecret,
		URIBase:           config.URIBase,
		ExpiresIn:         time.Hour,
		PublicKey:         publicKey,
		PrivateKey:        privateKey,
		Logger:            logger,
		Users:             users,
		Clients:           clients,
	}

	oidcServer, err := mockoidc.NewServer(srvConfig)
	if err != nil {
		panic(err)
	}

	mux := chi.NewMux()
	mux.Use(middleware.RequestID)
	mux.Use(middleware.RealIP)
	mux.Use(zaphttp.SetLogger(logger.Desugar(), zapchi.RequestID))
	mux.Use(middleware.RequestLogger(zapchi.LogFormatter()))
	mux.Use(middleware.Recoverer)

	mux.Get("/.well-known/openid-configuration", oidcServer.Discovery)
	mux.Get("/auth", oidcServer.AuthGet)
	mux.Post("/auth", oidcServer.AuthPost)
	mux.Post("/token", oidcServer.Token)
	mux.Get("/certs", oidcServer.Certs)
	mux.Get("/clear", oidcServer.Clear)

	srv := graceful.WithDefaults(&http.Server{
		Addr:         fmt.Sprintf("%s:%s", config.Host, config.Port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	})
	if err := graceful.Graceful(srv.ListenAndServe, srv.Shutdown); err != nil {
		panic(err)
	}
	logger.Info("gracefully stopped server")
}
