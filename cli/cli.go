package cli

import (
	"fmt"
	"os"
	"time"

	"github.com/caarlos0/env/v8"
	"github.com/spf13/cobra"
	"github.com/ugent-library/mock-oidc-server/mockoidc"
	"go.uber.org/zap"

	_ "github.com/joho/godotenv/autoload"
)

var logger *zap.SugaredLogger
var config Config
var store *mockoidc.Store
var rootCmd = &cobra.Command{
	Use: "mock-oidc-server",
}

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

func initStore() {
	expiresIn, err := time.ParseDuration(config.ExpiresIn)
	cobra.CheckErr(err)
	s, err := mockoidc.NewStore(config.DataPath, 100, expiresIn)
	cobra.CheckErr(err)
	store = s
}

func init() {
	cobra.OnInitialize(initConfig, initLogger, initStore)
	cobra.OnFinalize(func() {
		logger.Sync()
		if store != nil {
			if err := store.FlushToFile(); err != nil {
				fmt.Fprintf(os.Stderr, "unable to flush store: %s", err)
			}
		}
	})
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}
