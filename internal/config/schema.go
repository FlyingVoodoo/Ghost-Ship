package config

type Role string

const (
	RoleRelay Role = "relay"
	RoleExit  Role = "exit"
)

type Location string

const (
	LocationUS Location = "us"
	LocationEU Location = "eu"
	LocationRU Location = "ru"
	LocationDE Location = "de"
)

type NodeManifest struct {
	Node     NodeConfig     `yaml:"node"`
	Firewall FirewallConfig `yaml:"firewall"`
	Services []ServiceSpec  `yaml:"services"`
	Nomad    NomadConfig    `yaml:"nomad"`
	Monitor  MonitorConfig  `yaml:"monitor"`
}

type NodeConfig struct {
	Role     Role     `yaml:"role"`
	Location Location `yaml:"location"`
	Hostname string   `yaml:"hostname"`
	IP       string   `yaml:"ip"`
	USERNAME string   `yaml:"username"`
}

type FirewallConfig struct {
	AllowPorts []int  `yaml:"allow_ports"`
	AllowSSH   bool   `yaml:"allow_ssh"`
	Backend    string `yaml:"backend"`
}

type ServiceSpec struct {
	Name     string            `yaml:"name"`
	Image    string            `yaml:"image"`
	Volumes  []string          `yaml:"volumes"`
	Env      map[string]string `yaml:"env"`
	Ports    []PortMapping     `yaml:"ports"`
	Count    int               `yaml:"count"`
	MemoryMB int               `yaml:"memory_mb"`
}

type PortMapping struct {
	Host      int    `yaml:"host"`
	Container int    `yaml:"container"`
	Protocol  string `yaml:"protocol"`
}

type NomadConfig struct {
	DataDir    string `yaml:"data_dir"`
	BindAddr   string `yaml:"bind_addr"`
	LogLevel   string `yaml:"log_level"`
	ServerMode bool   `yaml:"server_mode"`
}

type MonitorConfig struct {
	TelegramToken  string `yaml:"telegram_token"`
	TelegramChatID string `yaml:"telegram_chat_id"`
	Enabled        bool   `yaml:"enabled"`
}
