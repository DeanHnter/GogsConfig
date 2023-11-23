package gogsconfig

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/go-ini/ini"
)

const (
	iniContent = `[app]
BRAND_NAME = Gogs
RUN_USER = git
RUN_MODE = dev

[database]
TYPE = postgres
HOST = 127.0.0.1:5432
NAME = gogs
USER = gogs
PASSWORD =
SSL_MODE = disable
PATH = data/gogs.db

[repository]
ROOT = 
DEFAULT_BRANCH = master

[server]
DOMAIN = localhost
HTTP_PORT = 3000
EXTERNAL_URL = http://localhost:3000/
DISABLE_SSH = false
SSH_PORT = 22
START_SSH_SERVER = false
OFFLINE_MODE = false

[email]
ENABLED = false

[auth]
REQUIRE_EMAIL_CONFIRMATION = false
DISABLE_REGISTRATION = false
ENABLE_REGISTRATION_CAPTCHA = true
REQUIRE_SIGNIN_VIEW = false

[user]
ENABLE_EMAIL_NOTIFICATION = false

[picture]
DISABLE_GRAVATAR = false
ENABLE_FEDERATED_AVATAR = false

[session]
PROVIDER = memory

[log]
MODE = console
LEVEL = Trace
ROOT_PATH =

[security]
INSTALL_LOCK = false
SECRET_KEY = !#@FDEWREWR&*(
`
)

type Database struct {
	Type     string `ini:"TYPE"`
	Host     string `ini:"HOST"`
	Name     string `ini:"NAME"`
	Schema   string
	User     string `ini:"USER"`
	Password string `ini:"PASSWORD"`
	SSLMode  string `ini:"SSL_MODE"`
	Path     string `ini:"PATH"`
}

type Repository struct {
	Root          string `ini:"ROOT"`
	DefaultBranch string `ini:"DEFAULT_BRANCH"`
}

type Server struct {
	Domain         string `ini:"DOMAIN"`
	HTTPPort       int    `ini:"HTTP_PORT"`
	ExternalURL    string `ini:"EXTERNAL_URL"`
	DisableSSH     bool   `ini:"DISABLE_SSH"`
	SSHPort        int    `ini:"SSH_PORT"`
	StartSSHServer bool   `ini:"START_SSH_SERVER"`
	OfflineMode    bool   `ini:"OFFLINE_MODE"`
}

type Mailer struct {
	Enabled bool `ini:"ENABLED"`
}

type Auth struct {
	RequireEmailConfirmation  bool `ini:"REQUIRE_EMAIL_CONFIRMATION"`
	DisableRegistration       bool `ini:"DISABLE_REGISTRATION"`
	EnableRegistrationCaptcha bool `ini:"ENABLE_REGISTRATION_CAPTCHA"`
	RequireSigninView         bool `ini:"REQUIRE_SIGNIN_VIEW"`
}

type User struct {
	EnableEmailNotification bool `ini:"ENABLE_EMAIL_NOTIFICATION"`
}

type Picture struct {
	DisableGravatar       bool `ini:"DISABLE_GRAVATAR"`
	EnableFederatedAvatar bool `ini:"ENABLE_FEDERATED_AVATAR"`
}

type Session struct {
	Provider string `ini:"PROVIDER"`
}

type Log struct {
	Mode     string `ini:"MODE"`
	Level    string `ini:"LEVEL"`
	RootPath string `ini:"ROOT_PATH"`
}

type Security struct {
	InstallLock bool   `ini:"INSTALL_LOCK"`
	SecretKey   string `ini:"SECRET_KEY"`
}

type GogsConfig struct {
	BrandName string `ini:"app:BRAND_NAME"`
	RunUser   string `ini:"app:RUN_USER"`
	RunMode   string `ini:"app:RUN_MODE"`

	GogDatabase Database `ini:"database"`

	GogRepository Repository `ini:"repository"`

	GogServer Server `ini:"server"`

	GogMailer Mailer `ini:"email"`

	GogAuth Auth `ini:"auth"`

	GogUser User `ini:"user"`

	GogPicture Picture `ini:"picture"`

	GogSession Session `ini:"session"`

	GogLog Log `ini:"log"`

	GogSecurity Security `ini:"security"`
}

func NewGogsConfig() (*GogsConfig, error) {
    cfg, err := ini.InsensitiveLoad([]byte(iniContent))
    if err != nil {
        fmt.Printf("Fail to load ini content: %v", err)
        return nil, errors.New("Fail to load ini content")
    }

    var config GogsConfig
    err = cfg.MapTo(&config)
    if err != nil {
        fmt.Printf("Fail to map data: %v", err)
        return nil, errors.New("Fail to map data")
    }

    return &config, nil
}

func LoadConfig(path string) (*GogsConfig, error) {
	cfg, err := ini.InsensitiveLoadFromFile(path)
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
		return nil, errors.New("Fail to read file")
	}

	config := new(GogsConfig)
	if err = cfg.Section("app").MapTo(&config); err != nil {
		fmt.Printf("Fail to map app section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("database").MapTo(&config.GogDatabase); err != nil {
		fmt.Printf("Fail to map database section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("repository").MapTo(&config.GogDatabase); err != nil {
		fmt.Printf("Fail to map database section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("server").MapTo(&config.GogDatabase); err != nil {
		fmt.Printf("Fail to map database section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("email").MapTo(&config.GogDatabase); err != nil {
		fmt.Printf("Fail to map database section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("auth").MapTo(&config.GogDatabase); err != nil {
		fmt.Printf("Fail to map database section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("user").MapTo(&config.GogDatabase); err != nil {
		fmt.Printf("Fail to map database section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("picture").MapTo(&config.GogDatabase); err != nil {
		fmt.Printf("Fail to map database section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("session").MapTo(&config.GogDatabase); err != nil {
		fmt.Printf("Fail to map database section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("log").MapTo(&config.GogDatabase); err != nil {
		fmt.Printf("Fail to map database section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("security").MapTo(&config.GogDatabase); err != nil {
		fmt.Printf("Fail to map database section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	return config, nil
}

func SaveConfig(path string, gogsConfig *GogsConfig) error {
	cfg := ini.Empty()
	err := cfg.ReflectFrom(gogsConfig)
    if err != nil {
		return err
	}

	var emptySections []string

	for _, section := range cfg.Sections() {
		for key, value := range section.KeysHash() {
			if value == "" || value == "0" {
				section.DeleteKey(key)
			}
		}

		if len(section.Keys()) == 0 {
			emptySections = append(emptySections, section.Name())
		}
	}

	for _, sectionName := range emptySections {
		cfg.DeleteSection(sectionName)
	}
	
    err = cfg.SaveTo(path)
	if err != nil {
		return err
	}

	return nil
}
