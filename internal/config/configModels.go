package config

import "time"

type Config struct {
	Env        string           `yaml:"env" env-default:"local"`
	HttpServer HttpServerConfig `yaml:"httpServer" env-required:"true"`
	Socks5Proxy  socks5proxyConfig `yaml:"socks5proxy" env-required:"true"`
	DBConfig   DBConfig         `yaml:"db" env-required:"true"`
	BotConfig  BotConfig        `yaml:"bot" env-required:"true"`
	configPath string
	//MigrationsPath string
	//TokenTTL       time.Duration `yaml:"token_ttl" env-default:"1h"`
}

type HttpServerConfig struct {
	Address string        `yaml:"address" env-required:"true" env-default:"localhost"`
	Port    string        `yaml:"port" env-required:"true" env-default:"8080"`
	Timeout time.Duration `yaml:"timeout" env-default:"5"`
	Secret  string        `yaml:"secret" env-required:"true" env-default:"secret"`
}

type socks5proxyConfig struct {
	Address string        `yaml:"address" env-required:"true" env:"SOCKS5PROXY_ADDRESS" env-default:"0.0.0.0"`
	Port    string        `yaml:"port" env-required:"true" env:"SOCKS5PROXY_PORT" env-default:"1080"`
}

type DBConfig struct {
	Host     string `yaml:"host" env:"DB_HOST" env-default:"localhost"`
	Port     string `yaml:"port" env:"DB_PORT" env-default:"5432"`
	Name     string `yaml:"name" env:"DB_NAME" env-default:"postgres"`
	User     string `yaml:"user" env:"DB_USER" env-default:"user"`
	Password string `yaml:"password" env:"DB_PASSWORD" env-default:"password"`
}

type AIConfig struct {
	Timeout         int     `yaml:"timeout" env:"AI_TIMEOUT" env-required:"true" env-default:"300"`
	BaseURL         string  `yaml:"baseURL" env:"AI_BASE_URL" env-required:"true"`
	ModelName       string  `yaml:"modelName" env:"AI_MODEL_NAME" env-required:"true"`
	AIApiToken      string  `yaml:"aiapitoken" env:"AI_API_TOKEN"`
	SystemRolePromt string  `yaml:"systemRolePromt" env-default:""`
	MaxTokens       int     `yaml:"maxTokens" env-default:"4096"`
	Temperature     float32 `yaml:"temperature" env-default:"0.5"`
	N               int     `yaml:"n" env-default:"1"`
}

type BotConfig struct {
	Admins        []string `yaml:"admins" env-default:"KrAssor"`
	TgbotApiToken string   `yaml:"tgbot_apitoken" env:"TGBOT_APITOKEN"`
	AI            AIConfig `yaml:"AI"`
}
