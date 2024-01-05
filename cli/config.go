package cli

type Config struct {
	Production        bool   `env:"PRODUCTION"`
	SessionCookieName string `env:"SESSION_COOKIE_NAME" envDefault:"MOCK_OIDC_SESSION"`
	URIBase           string `env:"URI_BASE" envDefault:"http://localhost:3000"`
	ExpiresIn         string `env:"EXPIRES_IN,required" envDefault:"1h"`
	PublicKeyPath     string `env:"PUBLIC_KEY_PATH" envDefault:".data/oidc.rsa.pub"`
	PublicKey         string `env:"PUBLIC_KEY"`
	PrivateKeyPath    string `env:"PRIVATE_KEY_PATH" envDefault:".data/oidc.rsa"`
	PrivateKey        string `env:"PRIVATE_KEY"`
	Host              string `env:"HOST" envDefault:"0.0.0.0"`
	Port              string `env:"PORT" envDefault:"3000"`
	ClientsPath       string `env:"CLIENTS_PATH" envDefault:".data/clients.json"`
	Clients           string `env:"CLIENTS"`
	UsersPath         string `env:"USERS_PATH" envDefault:".data/users.json"`
	Users             string `env:"USERS"`
}
