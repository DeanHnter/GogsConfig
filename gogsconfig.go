package gogsconfig

import (
	"errors"
	"fmt"
        "io/ioutil"
        "net/url"
        "math/rand"
        "net/http"
        "time"
	"strings"
	
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

//structure of payload gogs expects to install
type Payload struct {
    AdminConfirmPasswd    string
    AdminEmail            string
    AdminName             string
    AdminPasswd           string
    AppName               string
    AppURL                string
    DBHost                string
    DBName                string
    DBPasswd              string
    DBPath                string
    DBSchema              string
    DBType                string
    DBUser                string
    DefaultBranch         string
    Domain                string
    EnableCaptcha         string
    HTTPPort              string
    LogRootPath           string
    RepoRootPath          string
    RunUser               string
    SMTPFrom              string
    SMTPHost              string
    SMTPPasswd            string
    SMTPUser              string
    SSHPort               string
    SSLMode               string
}

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
	AdminName string
	AdminPassword string
	AdminEmail string
	AdminConfirmPassword string
	
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

func CreatePayload(cfg *GogsConfig) string {
    p := Payload{
        AdminConfirmPasswd:   cfg.AdminConfirmPassword,
        AdminEmail:           cfg.AdminEmail,
        AdminName:            cfg.AdminName,
        AdminPasswd:          cfg.AdminPassword,
        AppName:              cfg.BrandName,
        AppURL:               cfg.GogServer.ExternalURL,
        DBHost:               cfg.GogDatabase.Host,
        DBName:               cfg.GogDatabase.Name,
        DBPassword:           cfg.GogDatabase.Password,
        DBPath:               cfg.GogDatabase.Path,
        DBSchema:             cfg.GogDatabase.Schema,
        DBtype:               cfg.GogDatabase.Host,
        DBUser:               cfg.GogDatabase.User,
        DefaultBranch:        cfg.GogRepository.DefaultBranch,
        Domain:               cfg.GogServer.Domain,
        EnableCaptcha:        "on",
        HTTPPort:             cfg.GogServer.HTTPPort,
        LogRootPath:          cfg.Log.RootPath,
        RepoRootPath:         cfg.GogRepository.Root,
        RunUser:              cfg.RunUser,
        SMTPFrom:             "",
        SMTPHost:             "",
        SMTPPassword:         "",
        SMTPUser:             "",
        SSHPort:              cfg.GogServer.SSHPort,
        SSLMode:              cfg.GogDatabase.SSLMode,
    }

    data := url.Values{}
    data.Set("admin_confirm_passwd", p.AdminConfirmPassword)
    data.Set("admin_email", p.AdminEmail)
    data.Set("admin_name", p.AdminName)
    data.Set("admin_passwd", p.AdminPassword)
    data.Set("app_name", p.AppName)
    data.Set("app_url", p.AppURL)
    data.Set("db_host", p.DBHost)
    data.Set("db_name", p.DBName)
    data.Set("db_passwd", p.DBPassword)
    data.Set("db_path", p.DBPath)
    data.Set("db_schema", p.DBSchema)
    data.Set("db_type", p.DBtype)
    data.Set("db_user", p.DBUser)
    data.Set("default_branch", p.DefaultBranch)
    data.Set("domain", p.Domain)
    data.Set("enable_captcha", p.EnableCaptcha)
    data.Set("http_port", p.HTTPPort)
    data.Set("log_root_path", p.LogRootPath)
    data.Set("repo_root_path", p.RepoRootPath)
    data.Set("run_user", p.RunUser)
    data.Set("smtp_from", p.SMTPFrom)
    data.Set("smtp_host", p.SMTPHost)
    data.Set("smtp_passwd", p.SMTPPassword)
    data.Set("smtp_user", p.SMTPUser)
    data.Set("ssh_port", p.SSHPort)
    data.Set("ssl_mode", p.SSLMode)

    return data.Encode()
}

func createRequest(method string, url string, payloadString string) (*http.Request, error) {
  payload := strings.NewReader(payloadString)
  req, err := http.NewRequest(method, url, payload)

  if err != nil {
    return nil, err
  }

  setHeaders(req)

  return req, nil
}

func randomBrowserConfiguration() (string, string, string, string) {
    secChUa := []string{
        "\"Google Chrome\";v=\"119\", \"Chromium\";v=\"119\", \"Not?A_Brand\";v=\"24\"",
        "\"Google Chrome\";v=\"89\", \"Chromium\";v=\"89\", \"Not A Brand\";v=\"99\"",
    }

    secChUaMobile := []string{"?0", "?1"}

    secChUaPlatform := []string{"\"Windows\"", "\"macOS\"", "\"Android\"", "\"Linux\""}

    userAgent := []string{
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36",
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    }

    rand.Seed(time.Now().Unix())
    return secChUa[rand.Intn(len(secChUa))], secChUaMobile[rand.Intn(len(secChUaMobile))], secChUaPlatform[rand.Intn(len(secChUaPlatform))], userAgent[rand.Intn(len(userAgent))]
}


func setHeaders(req *http.Request) {
    secChUa, secChUaMobile, secChUaPlatform, userAgent := randomBrowserConfiguration()
    req.Header.Add("sec-ch-ua", secChUa)
    req.Header.Add("sec-ch-ua-mobile", secChUaMobile)
    req.Header.Add("sec-ch-ua-platform", secChUaPlatform)
    req.Header.Add("Upgrade-Insecure-Requests", "1")
    req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
    req.Header.Add("User-Agent", userAgent)
    req.Header.Add("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7")
    req.Header.Add("host", "localhost")
    req.Header.Add("Cookie", "id_token=value")
}

func sendRequest(req *http.Request) error {
  client := &http.Client{}
  res, err := client.Do(req)
  if err != nil {
    return err
  }
  defer res.Body.Close()

  body, err := ioutil.ReadAll(res.Body)
  if err != nil {
    return err
  }
	
  return nil
}

func SetupGogs(cfg *GogsConfig) error {
    url := "http://localhost:3000/install"
    method := "POST"

    payload := createPayload(cfg)
    req, err := createRequest(method, url, payload)
    if err != nil {
        return err
    }
    err = sendRequest(req)
    return err
}

func NewGogsConfig() (*GogsConfig, error) {
    cfg, err := ini.LoadSources(ini.LoadOptions{
        IgnoreInlineComment: true,
    }, []byte(iniContent))
    if err != nil {
        fmt.Printf("Fail to parse INI data: %v", err)
        return nil, errors.New("Fail to parse INI data")
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
	cfg, err := ini.LoadSources(ini.LoadOptions{Insensitive: true}, path)
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
	if err = cfg.Section("repository").MapTo(&config.GogRepository); err != nil {
		fmt.Printf("Fail to map repository section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("server").MapTo(&config.GogServer); err != nil {
		fmt.Printf("Fail to map server section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("email").MapTo(&config.GogMailer); err != nil {
		fmt.Printf("Fail to map email section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("auth").MapTo(&config.GogAuth); err != nil {
		fmt.Printf("Fail to map auth section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("user").MapTo(&config.GogUser); err != nil {
		fmt.Printf("Fail to map database section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("picture").MapTo(&config.GogPicture); err != nil {
		fmt.Printf("Fail to map picture section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("session").MapTo(&config.GogSession); err != nil {
		fmt.Printf("Fail to map session section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("log").MapTo(&config.GogLog); err != nil {
		fmt.Printf("Fail to map log section: %v", err)
		return nil, errors.New("Fail to map data")
	}
	if err = cfg.Section("security").MapTo(&config.GogSecurity); err != nil {
		fmt.Printf("Fail to map security section: %v", err)
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
