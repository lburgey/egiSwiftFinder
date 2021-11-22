package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"time"

	"github.com/indigo-dc/liboidcagent-go"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
)

const (
	DefaultConfigURL = "https://raw.githubusercontent.com/tdviet/fedcloudclient/master/config/sites.yaml"
	GOCDBPublicURL   = "https://goc.egi.eu/gocdbpi/public/"
)

var (
	argOIDCAgentAccount = kingpin.Flag("oidc-agent", "oidc-agent account shortname").Short('o').Envar("OIDC_AGENT_ACCOUNT").String()
	argVO               = kingpin.Flag("vo", "virtual organisation to use").Short('v').Envar("EGI_VO").String()
	argSite             = kingpin.Flag("site", "Site").Short('s').Envar("EGI_SITE").String()
)

type UserInfo struct {
	Entitlements []string `json:"eduperson_entitlement"`
}

type Config struct {
	AccessToken string
	Issuer      string
	VO          string
	Sites       []*Site
}

type Site struct {
	Config *SiteConfig
	Auth   *SiteAuth
}

func (s *Site) String() (name string) {
	if s != nil {
		return s.Config.Name
	}
	return
}

type SiteConfig struct {
	Name     string `yaml:"gocdb"`
	Endpoint string `yaml:"endpoint"`
	VOs      []struct {
		Name string `yaml:"name"`
		Auth struct {
			ProjectID string `yaml:"project_id"`
		} `yaml:"auth"`
	} `yaml:"vos"`
}

type SiteAuth struct {
	UnscopedToken     string
	Token             Token
	SwiftCatalogEntry *CatalogEntry
	SwiftEndpoint     *Endpoint
}

type CatalogEntry struct {
	Type      string     `json:"type"`
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Endpoints []Endpoint `json:"endpoints"`
}

type Endpoint struct {
	URL       string `json:"url"`
	Interface string `json:"interface"`
	Region    string `json:"region"`
	RegionID  string `json:"region_id"`
	ID        string `json:"id"`
}

// AuthResponse to calls no /v3/auth/tokens
type AuthResponse struct {
	Token *Token `json:"token"`
}

type Token struct {
	AuditIDs  []string       `json:"audit_ids"`
	IssuedAt  *time.Time     `json:"issued_at"`
	ExpiresAt *time.Time     `json:"expires_at"`
	Catalog   []CatalogEntry `json:"catalog"`
	User      *TokenUser     `json:"user"`
}

type TokenUser struct {
	OSFederation struct {
		IdentityProvider struct {
			ID string `json:"id"`
		} `json:"identity_provider"`
		Protocol struct {
			ID string `json:"id"`
		} `json:"protocol"`
		Groups []struct {
			ID string `json:"id"`
		} `json:"groups"`
	} `json:"OS-FEDERATION"`
	Domain struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"domain"`
	ID   string `json:"id"`
	Name string `json:"name"`
}

func fetchConfigPaths() (configPaths []string, err error) {
	resp, err := http.Get(DefaultConfigURL)
	if err != nil {
		return nil, err
	}
	var bodyBytes []byte
	bodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(bodyBytes, &configPaths)
	return
}

func fetchSiteConfig(path string) (config *SiteConfig, err error) {
	var resp *http.Response
	resp, err = http.Get(path)
	if err != nil {
		return
	}
	var bodyBytes []byte
	bodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	config = new(SiteConfig)
	err = yaml.Unmarshal(bodyBytes, config)
	if err != nil {
		return
	}
	config.Endpoint = strings.TrimSuffix(config.Endpoint, "/")
	return
}

func (c *Config) Fetch() (err error) {
	// fmt.Println("Fetching site configurations")
	var configPaths []string
	configPaths, err = fetchConfigPaths()
	if err != nil {
		return
	}

	c.Sites = make([]*Site, len(configPaths))

	wg := sync.WaitGroup{}
	wg.Add(len(configPaths))
	for i, path := range configPaths {
		c.Sites[i] = new(Site)
		go func(i int, path string) {
			var config *SiteConfig
			config, err = fetchSiteConfig(path)
			if err == nil {
				c.Sites[i].Config = config
			} else {
				fmt.Printf("Failed to fetch config from %s\n", path)
			}
			wg.Done()
		}(i, path)
	}
	wg.Wait()
	return
}

func getOIDCAgentAccount() (accountName string, err error) {
	if *argOIDCAgentAccount != "" {
		accountName = *argOIDCAgentAccount
		return
	}
	loadedAccounts, err := liboidcagent.GetLoadedAccounts()
	if err != nil {
		return
	}
	loadedLen := len(loadedAccounts)
	if loadedLen == 0 {
		err = fmt.Errorf("no loaded oidc agent accounts") // TODO instructions
		return
	} else if loadedLen == 1 {
		accountName = loadedAccounts[0]
		fmt.Printf("Using the only loaded oidc-agent account: %s\n", accountName)
		return
	}
	fmt.Printf("Select a loaded oidc-agent account:\n")
	accountName = selectString(loadedAccounts)
	return
}

func getAT() (at string, issuer string, err error) {
	var accountName string
	accountName, err = getOIDCAgentAccount()
	if err != nil {
		return
	}

	req := liboidcagent.TokenRequest{ShortName: accountName}
	var tr liboidcagent.TokenResponse
	tr, err = liboidcagent.GetTokenResponse(req)
	if err != nil {
		return
	}
	at = tr.Token
	issuer = tr.Issuer
	return
}

func getUserInfo(c *Config) (ui UserInfo, err error) {
	var req *http.Request
	req, err = http.NewRequest("GET", c.Issuer+"/userinfo", nil) // TODO look this up in the well known config
	if err != nil {
		return
	}
	req.Header.Add("Authorization", fmt.Sprintf("Bearer %s", c.AccessToken))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != 200 {
		err = fmt.Errorf("user info request: %v - %s", resp.Status, bodyBytes)
		return
	}
	err = json.Unmarshal(bodyBytes, &ui)
	return
}

func getVO(userinfo UserInfo) (vo string, err error) {
	if *argVO != "" {
		vo = *argVO
		fmt.Printf("Using VO: %s\n", vo)
		return
	}

	fmt.Println("Select a VO:")
	vo = selectString(userinfo.Entitlements)
	return
}

func (c *Config) SetUserAuth() (err error) {
	c.AccessToken, c.Issuer, err = getAT()
	if err != nil {
		return
	}

	var userinfo UserInfo
	userinfo, err = getUserInfo(c)
	if err != nil {
		return
	}

	c.VO, err = getVO(userinfo)
	return
}

func (c *Config) GetSiteByName(name string) (site *Site) {
	for _, s := range c.Sites {
		if s.Config.Name == name {
			site = s
			return
		}
	}
	return
}

func (c *Config) GetSwiftSitesForVO() (sites []string) {
	sites = []string{}
	pos := make(chan string)

	wg := sync.WaitGroup{}
	wg.Add(len(c.Sites))

	go func() {
		for {
			site, ok := <-pos
			if !ok {
				break
			}
			sites = append(sites, site)
		}
	}()

	for _, site := range c.Sites {
		go func(s *Site) {
			if s.HasAvailableSwiftEndpoint(c) {
				pos <- s.Config.Name
			}
			wg.Done()
		}(site)
	}
	wg.Wait()
	close(pos)

	// original: 6.5s -> parallel ~1.2
	return
}

func (s *Site) getUnscopedToken(at string) (unscopedToken string, err error) {
	idp := "egi.eu"
	authProtocol := "openid"
	url := fmt.Sprintf("%s/OS-FEDERATION/identity_providers/%s/protocols/%s/auth",
		s.Config.Endpoint, idp, authProtocol)
	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+at)

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode != 201 {
		err = fmt.Errorf("requesting unscoped token: %s", resp.Status)
		return
	}
	unscopedToken = resp.Header.Get("X-Subject-Token")
	return
}

func (c SiteConfig) projectForVO(selectedVO string) (projectID string) {
	for _, vo := range c.VOs {
		if strings.Contains(selectedVO, vo.Name) {
			return vo.Auth.ProjectID
		}
	}
	return
}

// https://docs.openstack.org/api-ref/identity/v3/index.html#authentication-and-token-management
func (s *Site) getScopedTokenInfo(auth *SiteAuth, vo string) (parsedAuthResponse AuthResponse, err error) {
	url := s.Config.Endpoint
	if !strings.HasSuffix(url, "/") {
		url += "/"
	}
	url += "auth/tokens"

	type AuthReq struct {
		Auth struct {
			Identity struct {
				Methods []string `json:"methods"`
				Token   struct {
					ID string `json:"id"`
				} `json:"token"`
			} `json:"identity"`
			Scope struct {
				Project struct {
					ID string `json:"id"`
				} `json:"project"`
			} `json:"scope"`
		} `json:"auth"`
	}

	var authReq AuthReq
	authReq.Auth.Identity.Token.ID = auth.UnscopedToken
	authReq.Auth.Scope.Project.ID = s.Config.projectForVO(vo)
	authReq.Auth.Identity.Methods = []string{"token"}

	reqBody, err := json.Marshal(authReq)
	if err != nil {
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return
	}

	var respBytes []byte
	respBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(respBytes, &parsedAuthResponse)
	if err != nil {
		return
	}
	return
}

func (s *Site) parseAuthResponse(auth *SiteAuth, authResponse AuthResponse) (err error) {
	if auth == nil {
		err = fmt.Errorf("auth is nil")
		return
	}
	if authResponse.Token == nil {
		err = fmt.Errorf("authResponse.Token is nil")
		return
	}
	auth.Token = *authResponse.Token
	for _, entry := range auth.Token.Catalog {
		if entry.Type == "object-store" {
			auth.SwiftCatalogEntry = &entry
			for _, endpoint := range entry.Endpoints {
				if endpoint.Interface == "public" {
					auth.SwiftEndpoint = &endpoint
					break
				}
			}
		}
	}
	return
}

func (s *Site) Authenticate(c *Config) (err error) {
	// fmt.Printf("Authenticating against site %s\n", s)
	auth := new(SiteAuth)
	auth.UnscopedToken, err = s.getUnscopedToken(c.AccessToken)
	if err != nil {
		return
	}
	var authResponse AuthResponse
	authResponse, err = s.getScopedTokenInfo(auth, c.VO)
	if err != nil {
		return
	}

	err = s.parseAuthResponse(auth, authResponse)
	if err != nil {
		return
	}

	s.Auth = auth
	return
}

func (s *Site) IsAuthenticated() bool {
	return s.Auth != nil && time.Until(*s.Auth.Token.ExpiresAt) > 0
}

func (s *Site) GetAuth(c *Config) (auth *SiteAuth, err error) {
	if s.IsAuthenticated() {
		auth = s.Auth
		return
	}
	err = s.Authenticate(c)
	auth = s.Auth
	return
}

func (s *Site) FindPublicSwiftEndpoint(c *Config) (endpoint *Endpoint, err error) {
	auth, err := s.GetAuth(c)
	if err != nil {
		return
	}
	endpoint = auth.SwiftEndpoint
	return
}

func (s *Site) HasAvailableSwiftEndpoint(c *Config) bool {
	available := false
	for _, siteVO := range s.Config.VOs {
		if strings.Contains(c.VO, siteVO.Name) {
			available = true
			break
		}
	}
	if available {
		endpoint, err := s.FindPublicSwiftEndpoint(c)
		if err != nil {
			fmt.Printf("Error finding endpoint: %v\n", err)
		} else if endpoint != nil {
			return true
		}
	}
	return false
}

func getSite(c *Config) (site *Site, err error) {
	// if the user has provided an site argument we check it
	if *argSite != "" {
		site = c.GetSiteByName(*argSite)
		if site == nil {
			err = fmt.Errorf("no site with this name found: %s", *argSite)
			return
		}
		if !site.HasAvailableSwiftEndpoint(c) {
			err = fmt.Errorf("the selected site %s provides no public swift endpoint for the selected VO %s", *argSite, c.VO)
			return
		}
		fmt.Printf("Using site: %s\n", site)
		return
	}

	sites := c.GetSwiftSitesForVO()
	if len(sites) == 0 {
		err = fmt.Errorf("no sites provide swift for the selected VO")
		return
	}

	fmt.Println("Select a site:")
	siteName := selectString(sites)
	site = c.GetSiteByName(siteName)
	if site == nil {
		err = fmt.Errorf("invalid choice: '%s'", siteName)
	}
	return
}

func run() (err error) {
	c := new(Config)
	err = c.Fetch()
	if err != nil {
		return
	}

	err = c.SetUserAuth()
	if err != nil {
		return
	}

	fmt.Printf("Searching sites providing swift for this VO\n")
	var site *Site
	site, err = getSite(c)
	if err != nil {
		return
	}

	endpoint, err := site.FindPublicSwiftEndpoint(c)
	if err != nil {
		return
	}
	fmt.Printf("Available swift endpoint: %s\n", endpoint.URL)
	return
}

// go-prompt eats Ctrl+C if we don't do this, see: https://github.com/c-bata/go-prompt/issues/228#issuecomment-820639887
func handleExit() {
	rawModeOff := exec.Command("/bin/stty", "-raw", "echo")
	rawModeOff.Stdin = os.Stdin
	_ = rawModeOff.Run()
	rawModeOff.Wait()
}

func main() {
	defer handleExit()

	intChan := make(chan os.Signal, 1)
	signal.Notify(intChan, os.Interrupt)
	go func() {
		<-intChan
		fmt.Printf("Exiting on user interrupt")
		os.Exit(0)
	}()

	kingpin.Parse()
	err := run()
	if err != nil {
		fmt.Printf("Error: %s", err)
	}
}
