package main

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ory/graceful"
	"github.com/spf13/cobra"
	"github.com/ugent-library/mock-oidc-server/oidc"
	"github.com/ugent-library/zaphttp"
	"github.com/ugent-library/zaphttp/zapchi"
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger

func initLogger() {
	l, e := zap.NewDevelopment()
	cobra.CheckErr(e)
	logger = l.Sugar()
}

func main() {
	initLogger()

	config := oidc.Config{
		SessionCookieName: "MOCK_OIDC_SESSION",
		SessionSecret:     "ABCDEFGH",
		URIBase:           "http://localhost:3000",
		ExpiresIn:         time.Hour,
		PublicKeyPath:     ".data/oidc.rsa.pub",
		PrivateKeyPath:    ".data/oidc.rsa",
		Logger:            logger,
		Users:             users,
		Clients:           clients,
	}

	oidcServer, err := oidc.NewServer(config)
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
