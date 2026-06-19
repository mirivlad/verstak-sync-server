package server

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type AdminUser struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
}

type Config struct {
	Port  int         `yaml:"port"`
	Admin []AdminUser `yaml:"admin"`
	mu    sync.Mutex
	path  string
}

func LoadConfig(dataDir string) (*Config, error) {
	path := filepath.Join(dataDir, "config.yml")
	cfg := &Config{
		Port:  47732,
		Admin: nil,
		path:  path,
	}
	data, err := os.ReadFile(path)
	if err == nil {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}
	}
	return cfg, nil
}

func (c *Config) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.saveLocked()
}

func (c *Config) SetAdmin(username, password string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	user := AdminUser{Username: username, PasswordHash: string(hash)}
	for i, u := range c.Admin {
		if u.Username == username {
			c.Admin[i] = user
			return c.saveLocked()
		}
	}
	c.Admin = append(c.Admin, user)
	return c.saveLocked()
}

func (c *Config) CheckAdmin(username, password string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, u := range c.Admin {
		if u.Username == username {
			if bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil {
				return true
			}
		}
	}
	return false
}

func (c *Config) saveLocked() error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path, data, 0640)
}
