// Package config handles loading bootstrap configuration from a .env file.
// Only minimal settings needed to connect to the database are stored here.
// All application settings (RPZ master, zones, sync interval, etc.) are
// stored in the PostgreSQL `settings` table and managed via the dashboard.
package config

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// BootstrapConfig holds the minimal configuration loaded from the .env file.
// It contains only what is needed before the database connection is established.
type BootstrapConfig struct {
	Server   ServerConfig
	Database DatabaseConfig
	Log      LogConfig
}

// ServerConfig holds the network listen addresses for the DNS and HTTP servers.
type ServerConfig struct {
	DNSAddress          string   // DNS_ADDRESS, e.g. "0.0.0.0:53"
	HTTPAddress         string   // HTTP_ADDRESS, e.g. "0.0.0.0:8080"
	RPZDefaultAction    string   // RPZ_DEFAULT_ACTION: nxdomain|nodata (default: nxdomain)
	DNSUpstreams        []string // DNS_UPSTREAM: comma-separated list of upstream resolvers
	DNSUpstreamStrategy string   // DNS_UPSTREAM_STRATEGY: roundrobin|random|race (default: roundrobin)
	DNSCacheSize        int      // DNS_CACHE_SIZE: max cached upstream responses, 0 = disabled (default: 100000)
	DNSAuditLog         bool     // DNS_AUDIT_LOG: log every query (client+name+type+result) at INFO level for audit (default: false)
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	DSN      string // DATABASE_DSN, e.g. "postgres://user:pass@host:5432/dbname"
	MaxConns int32  // DATABASE_MAX_CONNS (default: 20)
	MinConns int32  // DATABASE_MIN_CONNS (default: 2)
}

// LogConfig holds logging configuration.
type LogConfig struct {
	Level    string // LOG_LEVEL: debug, info, warn, error (default: info)
	Format   string // LOG_FORMAT: json, text (default: text)
	File     bool   // LOG_FILE: true = write logs to file, false = stdout only (default: false)
	FilePath string // LOG_FILE_PATH: path to log file (default: dns-rpz.log), only used when LOG_FILE=true
}

// AppSettings holds application settings stored in the database,
// editable at runtime via the dashboard.
type AppSettings struct {
	Mode         string // "master" or "slave"
	MasterIP     string // AXFR master IP (slave mode)
	MasterPort   int    // AXFR master port (default: 53)
	TSIGKey      string // TSIG key name (optional)
	TSIGSecret   string // TSIG secret base64 (optional)
	SyncInterval int    // zone sync interval in seconds (default: 300)
}

// Load reads and parses the bootstrap .env file at the given path.
// File format: KEY=VALUE, lines starting with # are comments, blank lines are ignored.
func Load(path string) (*BootstrapConfig, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open config file: %w", err)
	}
	defer f.Close()

	env := make(map[string]string)
	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("line %d: invalid format, expected KEY=VALUE", lineNum)
		}
		env[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &BootstrapConfig{}
	cfg.Server.DNSAddress = env["DNS_ADDRESS"]
	cfg.Server.HTTPAddress = env["HTTP_ADDRESS"]
	cfg.Server.RPZDefaultAction = env["RPZ_DEFAULT_ACTION"]
	cfg.Server.DNSUpstreamStrategy = env["DNS_UPSTREAM_STRATEGY"]
	if v, ok := env["DNS_UPSTREAM"]; ok && v != "" {
		for _, u := range strings.Split(v, ",") {
			if s := strings.TrimSpace(u); s != "" {
				cfg.Server.DNSUpstreams = append(cfg.Server.DNSUpstreams, s)
			}
		}
	}
	cfg.Database.DSN = env["DATABASE_DSN"]
	cfg.Log.Level = env["LOG_LEVEL"]
	cfg.Log.Format = env["LOG_FORMAT"]
	cfg.Log.FilePath = env["LOG_FILE_PATH"]

	if v, ok := env["LOG_FILE"]; ok {
		switch strings.ToLower(v) {
		case "true", "1", "yes":
			cfg.Log.File = true
		case "false", "0", "no", "":
			cfg.Log.File = false
		default:
			return nil, fmt.Errorf("LOG_FILE must be true or false")
		}
	}

	if v, ok := env["DATABASE_MAX_CONNS"]; ok {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("DATABASE_MAX_CONNS must be an integer")
		}
		cfg.Database.MaxConns = int32(n)
	}
	if v, ok := env["DATABASE_MIN_CONNS"]; ok {
		n, err := strconv.ParseInt(v, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("DATABASE_MIN_CONNS must be an integer")
		}
		cfg.Database.MinConns = int32(n)
	}
	if v, ok := env["DNS_CACHE_SIZE"]; ok {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			return nil, fmt.Errorf("DNS_CACHE_SIZE must be a non-negative integer")
		}
		cfg.Server.DNSCacheSize = n
	}
	if v, ok := env["DNS_AUDIT_LOG"]; ok {
		switch strings.ToLower(v) {
		case "true", "1", "yes":
			cfg.Server.DNSAuditLog = true
		case "false", "0", "no", "":
			cfg.Server.DNSAuditLog = false
		default:
			return nil, fmt.Errorf("DNS_AUDIT_LOG must be true or false")
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	cfg.setDefaults()
	return cfg, nil
}

func (c *BootstrapConfig) validate() error {
	if c.Database.DSN == "" {
		return fmt.Errorf("DATABASE_DSN is required")
	}
	if c.Server.DNSAddress == "" {
		return fmt.Errorf("DNS_ADDRESS is required")
	}
	return nil
}

func (c *BootstrapConfig) setDefaults() {
	if c.Database.MaxConns == 0 {
		c.Database.MaxConns = 20
	}
	if c.Database.MinConns == 0 {
		c.Database.MinConns = 2
	}
	if c.Server.HTTPAddress == "" {
		c.Server.HTTPAddress = "0.0.0.0:8080"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}
	if c.Log.File && c.Log.FilePath == "" {
		c.Log.FilePath = "dns-rpz.log"
	}
	if c.Server.RPZDefaultAction == "" {
		c.Server.RPZDefaultAction = "nxdomain"
	}
	if len(c.Server.DNSUpstreams) == 0 {
		c.Server.DNSUpstreams = []string{"8.8.8.8:53", "8.8.4.4:53"}
	}
	if c.Server.DNSUpstreamStrategy == "" {
		c.Server.DNSUpstreamStrategy = "roundrobin"
	}
	if c.Server.DNSCacheSize == 0 {
		c.Server.DNSCacheSize = 100_000
	}
}

// DefaultAppSettings returns sane defaults used on first run
// before any settings are saved to the database.
func DefaultAppSettings() *AppSettings {
	return &AppSettings{
		Mode:         "slave",
		MasterPort:   53,
		SyncInterval: 86400,
	}
}
