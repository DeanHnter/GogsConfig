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
	"strconv"
	"github.com/go-ini/ini"
	"golang.org/x/crypto/pbkdf2"
	"crypto/sha256"
	"crypto/subtle"
	"gorm.io/gorm"
)

// /////////////////////////////
// Taken from gogs /internal/userutil/userutil.go
func ValidatePassword(encoded, salt, password string) bool {
	got := EncodePassword(password, salt)
	return subtle.ConstantTimeCompare([]byte(encoded), []byte(got)) == 1
}

func EncodePassword(password, salt string) string {
	newPasswd := pbkdf2.Key([]byte(password), []byte(salt), 10000, 50, sha256.New)
	return fmt.Sprintf("%x", newPasswd)
}
// /////////////////////////////

type DatabaseType int

const (
    POSTGRES DatabaseType = iota
    MYSQL
    SQLITE3
    MSSQL
)

func (d DatabaseType) String() string {
    return [...]string{"postgres", "MySQL", "SQLite3", "mssql"}[d]
}

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

// for reading a gogs repository from db
type GogsRepository struct {
  ID                    uint   `gorm:"primarykey"`
  OwnerID               int 
  LowerName             string 
  Name                  string 
  Description           string 
  Website               string 
  DefaultBranch         string 
  Size                  int 
  UseCustomAvatar       int 
  NumWatches            int 
  NumStars              int 
  NumForks              int 
  NumIssues             int 
  NumClosedIssues       int 
  NumPulls              int 
  NumClosedPulls        int 
  NumMilestones         int 
  NumClosedMilestones   int 
  IsPrivate             int 
  IsUnlisted            int `gorm:"default:0"`
  IsBare                int 
  IsMirror              int 
  EnableWiki            int `gorm:"default:1"`
  AllowPublicWiki       int 
  EnableExternalWiki    int 
  ExternalWikiURL       string 
  EnableIssues          int `gorm:"default:1"`
  AllowPublicIssues     int 
  EnableExternalTracker int 
  ExternalTrackerURL    string 
  ExternalTrackerFormat string 
  ExternalTrackerStyle  string 
  EnablePulls           int `gorm:"default:1"`
  PullsIgnoreWhitespace int `gorm:"default:0"`
  PullsAllowRebase      int `gorm:"default:0"`
  IsFork                int `gorm:"default:0"`
  ForkID                int 
  CreatedUnix           int 
  UpdatedUnix           int 
}

// for reading a gogs user from db
type GogsUser struct {
	ID                    uint       `gorm:"primary_key:auto_increment"`
	LowerName             string     `gorm:"not null"`
	Name                  string     `gorm:"not null"`
	FullName              string
	Email                 string     `gorm:"not null"`
	Passwd                string     `gorm:"not null"`
	LoginSource           int        `gorm:"default:0"`
	LoginName             string
	Type                  int
	Location              string
	Website               string
	Rands                 string
	Salt                  string
	CreatedUnix           int
	UpdatedUnix           int
	LastRepoVisibility    int
	MaxRepoCreation       int        `gorm:"default:-1"`
	IsActive              int
	IsAdmin               int
	AllowGitHook          int
	AllowImportLocal      int
	ProhibitLogin         int
	Avatar                string     `gorm:"not null"`
	AvatarEmail           string     `gorm:"not null"`
	UseCustomAvatar       int
	NumFollowers          int
	NumFollowing          int        `gorm:"default:0"`
	NumStars              int
	NumRepos              int
	Description           string
	NumTeams              int
	NumMembers            int
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
	BrandName string
	RunUser   string
	RunMode   string
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
        DBPasswd:             cfg.GogDatabase.Password,
        DBPath:               cfg.GogDatabase.Path,
        DBSchema:             cfg.GogDatabase.Schema,
        DBType:               cfg.GogDatabase.Type,
        DBUser:               cfg.GogDatabase.User,
        DefaultBranch:        cfg.GogRepository.DefaultBranch,
        Domain:               cfg.GogServer.Domain,
        EnableCaptcha:        "on",
        HTTPPort:             strconv.Itoa(cfg.GogServer.HTTPPort),
        LogRootPath:          cfg.GogLog.RootPath,
        RepoRootPath:         cfg.GogRepository.Root,
        RunUser:              cfg.RunUser,
        SMTPFrom:             "",
        SMTPHost:             "",
        SMTPPasswd:         "",
        SMTPUser:             "",
        SSHPort:              strconv.Itoa(cfg.GogServer.SSHPort),
        SSLMode:              cfg.GogDatabase.SSLMode,
    }

    data := url.Values{}
    data.Set("admin_confirm_passwd", p.AdminConfirmPasswd)
    data.Set("admin_email", p.AdminEmail)
    data.Set("admin_name", p.AdminName)
    data.Set("admin_passwd", p.AdminPasswd)
    data.Set("app_name", p.AppName)
    data.Set("app_url", p.AppURL)
    data.Set("db_host", p.DBHost)
    data.Set("db_name", p.DBName)
    data.Set("db_passwd", p.DBPasswd)
    data.Set("db_path", p.DBPath)
    data.Set("db_schema", p.DBSchema)
    data.Set("db_type", p.DBType)
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
    data.Set("smtp_passwd", p.SMTPPasswd)
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

func sendRequest(req *http.Request, errorCh chan<- string) {
    defer close(errorCh) // Close channel on function return

    client := &http.Client{}
    start := time.Now()

    for {
        res, err := client.Do(req)
        if err != nil {
            errorCh <- "Error :"+err.Error() 
            time.Sleep(time.Second * 2)
            continue
        }

        if res.StatusCode >= 200 && res.StatusCode < 300 {
            body, err := ioutil.ReadAll(res.Body)
            if err != nil {
                errorCh <- err.Error()
                time.Sleep(time.Second * 2)
                continue
            }
	    if strings.Contains(string(body), `"ui negative message"`) {
		errorCh <- "Error in submitted configuration"
                time.Sleep(time.Second * 2)
                continue
	    } 
            
            res.Body.Close()
            return
        }
      
        errorCh <- fmt.Sprintf("Received status code: %d", res.StatusCode)

        if time.Since(start) >= time.Minute*3 {
            panic("no valid response within 3 minutes")
        }
    }
}

func SetupGogs(urlstr string, cfg *GogsConfig, errorCh chan<- string) error {
    method := "POST"
    payload := CreatePayload(cfg)

    req, err := createRequest(method, urlstr, payload)
    if err != nil {
        return err
    }

    sendRequest(req, errorCh)
    return nil
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
