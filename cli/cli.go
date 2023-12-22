package cli

import (
	"github.com/caarlos0/env/v8"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	_ "github.com/joho/godotenv/autoload"
)

var logger *zap.SugaredLogger
var config Config
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

func init() {
	cobra.OnInitialize(initConfig, initLogger)
	cobra.OnFinalize(func() {
		logger.Sync()
	})
}

func Execute() {
	cobra.CheckErr(rootCmd.Execute())
}
