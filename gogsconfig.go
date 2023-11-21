package gogsconfig

import (
	"html/template"
	"os"

	"github.com/go-ini/ini"
)


const (
	iniContent = `[App]
BRAND_NAME = {{.BrandName}}
RUN_USER = {{.RunUser}}
RUN_MODE = {{.RunMode}}

[GogDatabase]
TYPE = {{.GogDatabase.Type}}
HOST = {{.GogDatabase.Host}}
NAME = {{.GogDatabase.Name}}
SCHEMA = {{.GogDatabase.Schema}}
USER = {{.GogDatabase.User}}
PASSWORD = {{.GogDatabase.Password}}
SSL_MODE = {{.GogDatabase.SSLMode}}
PATH = {{.GogDatabase.Path}}

[GogRepository]
ROOT = {{.GogRepository.Root}}
DEFAULT_BRANCH = {{.GogRepository.DefaultBranch}}

[GogServer]
DOMAIN = {{.GogServer.Domain}}
HTTP_PORT = {{.GogServer.HTTPPort}}
EXTERNAL_URL = {{.GogServer.ExternalURL}}
DISABLE_SSH = {{.GogServer.DisableSSH}}
SSH_PORT = {{.GogServer.SSHPort}}
START_SSH_SERVER = {{.GogServer.StartSSHServer}}
OFFLINE_MODE = {{.GogServer.OfflineMode}}

[GogMailer]
ENABLED = {{.GogMailer.Enabled}}

[GogAuth]
REQUIRE_EMAIL_CONFIRMATION = {{.GogAuth.RequireEmailConfirmation}}
DISABLE_REGISTRATION = {{.GogAuth.DisableRegistration}}
ENABLE_REGISTRATION_CAPTCHA = {{.GogAuth.EnableRegistrationCaptcha}}
REQUIRE_SIGNIN_VIEW = {{.GogAuth.RequireSigninView}}

[GogUser]
ENABLE_EMAIL_NOTIFICATION = {{.GogUser.EnableEmailNotification}}

[GogPicture]
DISABLE_GRAVATAR = {{.GogPicture.DisableGravatar}}
ENABLE_FEDERATED_AVATAR = {{.GogPicture.EnableFederatedAvatar}}

[GogSession]
PROVIDER = {{.GogSession.Provider}}

[GogLog]
MODE = {{.GogLog.Mode}}
LEVEL = {{.GogLog.Level}}
ROOT_PATH = {{.GogLog.RootPath}}

[GogSecurity]
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

func LoadConfig(path string) (*GogsConfig, error) {
	cfg, err := ini.Load(path)
	if err != nil {
		return nil, err
	}

	gogsConfig := new(GogsConfig)
	err = cfg.MapTo(gogsConfig)
	if err != nil {
		return nil, err
	}

	return gogsConfig, nil
}

func SaveConfig(path string, gogsConfig *GogsConfig) error {
	t, err := template.New("GogsConfig").Parse(iniContent)
	if err != nil {
		return err
	}

	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	err = t.Execute(f, gogsConfig)
	if err != nil {
		return err
	}

	return nil
}
