package gogsconfig

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/go-ini/ini"
)

const (
	iniContent = `[App]
BRAND_NAME = {{.BrandName}}
RUN_USER = {{.RunUser}}
RUN_MODE = {{.RunMode}}

[database]
TYPE = {{.GogDatabase.Type}}
HOST = {{.GogDatabase.Host}}
NAME = {{.GogDatabase.Name}}
SCHEMA = {{.GogDatabase.Schema}}
USER = {{.GogDatabase.User}}
PASSWORD = {{.GogDatabase.Password}}
SSL_MODE = {{.GogDatabase.SSLMode}}
PATH = {{.GogDatabase.Path}}

[repository]
ROOT = {{.GogRepository.Root}}
DEFAULT_BRANCH = {{.GogRepository.DefaultBranch}}

[server]
DOMAIN = {{.GogServer.Domain}}
HTTP_PORT = {{.GogServer.HTTPPort}}
EXTERNAL_URL = {{.GogServer.ExternalURL}}
DISABLE_SSH = {{.GogServer.DisableSSH}}
SSH_PORT = {{.GogServer.SSHPort}}
START_SSH_SERVER = {{.GogServer.StartSSHServer}}
OFFLINE_MODE = {{.GogServer.OfflineMode}}

[email]
ENABLED = {{.GogMailer.Enabled}}

[GogAuth]
REQUIRE_EMAIL_CONFIRMATION = {{.GogAuth.RequireEmailConfirmation}}
DISABLE_REGISTRATION = {{.GogAuth.DisableRegistration}}
ENABLE_REGISTRATION_CAPTCHA = {{.GogAuth.EnableRegistrationCaptcha}}
REQUIRE_SIGNIN_VIEW = {{.GogAuth.RequireSigninView}}

[user]
ENABLE_EMAIL_NOTIFICATION = {{.GogUser.EnableEmailNotification}}

[picture]
DISABLE_GRAVATAR = {{.GogPicture.DisableGravatar}}
ENABLE_FEDERATED_AVATAR = {{.GogPicture.EnableFederatedAvatar}}

[session]
PROVIDER = {{.GogSession.Provider}}

[log]
MODE = {{.GogLog.Mode}}
LEVEL = {{.GogLog.Level}}
ROOT_PATH = {{.GogLog.RootPath}}

[security]
INSTALL_LOCK = {{.GogSecurity.InstallLock}}
SECRET_KEY = {{.GogSecurity.SecretKey}}
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

	err = cfg.SaveTo(path)
	if err != nil {
		return err
	}

	return nil
}
