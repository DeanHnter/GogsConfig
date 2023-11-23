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
	Type     string
	Host     string
	Name     string
	Schema   string
	User     string
	Password string
	SSLMode  string
	Path     string
}

type Repository struct {
	Root          string
	DefaultBranch string
}

type Server struct {
	Domain         string
	HTTPPort       int
	ExternalURL    string
	DisableSSH     bool
	SSHPort        int
	StartSSHServer bool
	OfflineMode    bool
}

type Mailer struct {
	Enabled bool
}

type Auth struct {
	RequireEmailConfirmation  bool
	DisableRegistration       bool
	EnableRegistrationCaptcha bool
	RequireSigninView         bool
}

type User struct {
	EnableEmailNotification bool
}

type Picture struct {
	DisableGravatar       bool
	EnableFederatedAvatar bool
}

type Session struct {
	Provider string
}

type Log struct {
	Mode     string
	Level    string
	RootPath string
}

type Security struct {
	InstallLock bool
	SecretKey   string
}

type GogsConfig struct {
	BrandName     string
	RunUser       string
	RunMode       string
	GogDatabase   Database
	GogRepository Repository
	GogServer     Server
	GogMailer     Mailer
	GogAuth       Auth
	GogUser       User
	GogPicture    Picture
	GogSession    Session
	GogLog        Log
	GogSecurity   Security
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
	content, err := os.ReadFile(path)
	if err != nil {
		log.Fatal(err)
	}

	cfg, err := ini.InsensitiveLoad(content)
	if err != nil {
		fmt.Printf("Fail to read file: %v", err)
		return nil, errors.New("Fail to read file")
	}

	var config GogsConfig
	err = cfg.MapTo(&config)
	if err != nil {
		fmt.Printf("Fail to map data: %v", err)
		return nil, errors.New("Fail to map data")
	}
	return &config, nil
}

func SaveConfig(path string, gogsConfig *GogsConfig) error {
	cfg := ini.Empty()
	err := cfg.ReflectFrom(gogsConfig)
	if err != nil {
		return err
	}
	
	for _, section := range cfg.Sections() {
		for key, value := range section.KeysHash() {
			if value == "" || value == "0" {
				section.DeleteKey(key)
			}
		}
	}
	
	err = cfg.SaveTo(path)
	if err != nil {
		return err
	}

	return nil
}
