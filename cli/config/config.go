package config

// Config -
type Config struct {
	Gateway        string `mapstructure:"gateway"`
	Port           string `mapstructure:"port"`
	PrivateKeyPath string `mapstructure:"private_key_path"`
}
