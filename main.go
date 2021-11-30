package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/adrg/xdg"
	"github.com/indigo-dc/liboidcagent-go"
	"gopkg.in/alecthomas/kingpin.v2"
	"gopkg.in/yaml.v2"
)

const (
	defaultTimeout   = 3 * time.Second
	defaultConfigURL = "https://raw.githubusercontent.com/tdviet/fedcloudclient/master/config/sites.yaml"

	// endpointType which we search at the sites
	endpointType            = "object-store"
	defaultRcloneRemoteName = "egiswift"
)

var (
	// version is set via: go build -ldflags '-X main.version=foobar'
	version               = ""
	rcloneConfigFile      = xdg.ConfigHome + "/rclone/rclone.conf"
	defaultCtx, defCancel = context.WithCancel(context.Background())
	argOIDCAgentAccount   = kingpin.Flag("oidc-agent", "oidc-agent account shortname").Short('o').Envar("OIDC_AGENT_ACCOUNT").String()
	argVO                 = kingpin.Flag("vo", "Virtual organisation").Short('v').Envar("EGI_VO").String()
	argSite               = kingpin.Flag("site", "Site").Short('s').Envar("EGI_SITE").String()

	// voRegex is used for extracting the group part from entitlements.
	voRegex = regexp.MustCompile("^(?:.+group:)(?P<vo>.+?)(?:(?:(?::admin)|:role=)|#)|$")
)

type userInfo struct {
	Entitlements []string `json:"eduperson_entitlement"`
}

func voFromEntitlement(ent string) (vo string) {
	matches := voRegex.FindStringSubmatch(ent)
	if len(matches) == 2 {
		return matches[1]
	}
	return
}

func (u *userInfo) getVOs() (vos []string) {
	vos = []string{}
	uniqueVOs := map[string]bool{}
	for _, ent := range u.Entitlements {
		uniqueVOs[voFromEntitlement(ent)] = true
	}
	for vo := range uniqueVOs {
		vos = append(vos, vo)
	}
	return
}

type userAuthParams struct {
	AccessToken string
	Issuer      string
	VO          string
}

type config struct {
	UserAuth *userAuthParams
	Sites    []*site
}

// site describe a site which may provide our service
// Config is populated in (*Config).Fetch()
// Auth is populated in when successfully calling (*site).Authenticate()
type site struct {
	Config *siteConfig
	Auth   *siteAuth
}

func (s *site) String() (name string) {
	if s != nil {
		return s.Config.Name
	}
	return
}

type siteConfig struct {
	Name     string `yaml:"gocdb"`
	Endpoint string `yaml:"endpoint"`
	VOs      []struct {
		Name string `yaml:"name"`
		Auth struct {
			ProjectID string `yaml:"project_id"`
		} `yaml:"auth"`
	} `yaml:"vos"`
}

type siteAuth struct {
	UnscopedToken     string
	ScopedToken       string
	TokenInfo         tokenInfo
	SwiftCatalogEntry *catalogEntry
	SwiftEndpoint     *endpoint
}

type catalogEntry struct {
	Type      string     `json:"type"`
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Endpoints []endpoint `json:"endpoints"`
}

type endpoint struct {
	URL       string `json:"url"`
	Interface string `json:"interface"`
	Region    string `json:"region"`
	RegionID  string `json:"region_id"`
	ID        string `json:"id"`
}

// authResponse to calls no /v3/auth/tokens
type authResponse struct {
	Token *tokenInfo `json:"token"`
}

// tokenInfo binds *some* of the fields of the auth response
// we don't need all the details here
type tokenInfo struct {
	AuditIDs  []string       `json:"audit_ids"`
	IssuedAt  *time.Time     `json:"issued_at"`
	ExpiresAt *time.Time     `json:"expires_at"`
	Catalog   []catalogEntry `json:"catalog"`
	User      *tokenUser     `json:"user"`
}

type tokenUser struct {
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
	resp, err := http.Get(defaultConfigURL)
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

func fetchSiteConfig(ctx context.Context, path string) (config *siteConfig, err error) {
	var (
		req  *http.Request
		resp *http.Response
	)
	req, err = http.NewRequestWithContext(ctx, "GET", path, nil)
	if err != nil {
		return
	}
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	var bodyBytes []byte
	bodyBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	config = new(siteConfig)
	err = yaml.Unmarshal(bodyBytes, config)
	if err != nil {
		return
	}
	config.Endpoint = strings.TrimSuffix(config.Endpoint, "/")
	return
}

func (c *config) Fetch() (err error) {
	ctx, cancel := context.WithTimeout(defaultCtx, defaultTimeout)
	defer cancel()

	var configPaths []string
	configPaths, err = fetchConfigPaths()
	if err != nil {
		return
	}

	c.Sites = make([]*site, len(configPaths))

	wg := sync.WaitGroup{}
	wg.Add(len(configPaths))
	for i, path := range configPaths {
		c.Sites[i] = new(site)
		go func(i int, path string) {
			var config *siteConfig
			config, err = fetchSiteConfig(ctx, path)
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

func newConfig() (c *config, err error) {
	c = new(config)
	err = c.Fetch()
	if err != nil {
		return
	}

	err = c.SetUserAuth()
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
		err = printSelected("oidc-agent account", accountName)
		return
	}

	accountName, err = selectString("oidc-agent account", loadedAccounts)
	return
}

func (ua *userAuthParams) getAT() (err error) {
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
	ua.AccessToken = tr.Token
	ua.Issuer = tr.Issuer
	return
}

func (ua *userAuthParams) getUserInfo(c *config) (ui userInfo, err error) {
	ctx, cancel := context.WithTimeout(defaultCtx, defaultTimeout)
	defer cancel()

	var req *http.Request
	req, err = http.NewRequestWithContext(ctx, "GET", ua.Issuer+"/userinfo", nil) // TODO look this up in the well known config
	if err != nil {
		return
	}
	req.Header.Add("Authorization", "Bearer "+ua.AccessToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("user info request: %v - %s", resp.Status, bodyBytes)
		return
	}
	err = json.Unmarshal(bodyBytes, &ui)
	return
}

func (ua *userAuthParams) getVO(userinfo userInfo) (err error) {
	if *argVO != "" {
		ua.VO = *argVO
		err = printSelected("VO", ua.VO)
		return
	}

	vos := userinfo.getVOs()
	ua.VO, err = selectString("VO", vos)
	return
}

func (c *config) SetUserAuth() (err error) {
	ua := new(userAuthParams)
	err = ua.getAT()
	if err != nil {
		return
	}

	var userinfo userInfo
	userinfo, err = ua.getUserInfo(c)
	if err != nil {
		return
	}

	err = ua.getVO(userinfo)
	if err != nil {
		return
	}
	c.UserAuth = ua
	return
}

func (c *config) GetSiteByName(name string) *site {
	for _, s := range c.Sites {
		if s.Config.Name == name {
			return s
		}
	}
	return nil
}

func (c *config) GetSwiftSitesForVO() (sites []string) {
	sites = []string{}
	swiftSites := make(chan string)

	wg := sync.WaitGroup{}
	wg.Add(len(c.Sites))

	go func() {
		for {
			swiftSite, ok := <-swiftSites
			if !ok {
				break
			}
			sites = append(sites, swiftSite)
		}
	}()

	for _, s := range c.Sites {
		go func(s *site) {
			if s.hasAvailableSwiftEndpoint(c.UserAuth) {
				swiftSites <- s.Config.Name
			}
			wg.Done()
		}(s)
	}
	wg.Wait()
	close(swiftSites)

	// original: 6.5s -> parallel ~1.2
	return
}

func (s *site) getUnscopedToken(ctx context.Context, at string) (unscopedToken string, err error) {
	idp := "egi.eu"
	authProtocol := "openid"
	url := fmt.Sprintf("%s/OS-FEDERATION/identity_providers/%s/protocols/%s/auth",
		s.Config.Endpoint, idp, authProtocol)
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+at)

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusCreated {
		err = fmt.Errorf("requesting unscoped token: %s", resp.Status)
		return
	}
	unscopedToken = resp.Header.Get("X-Subject-Token")
	return
}

func (c siteConfig) projectForVO(selectedVO string) (projectID string) {
	for _, vo := range c.VOs {
		if strings.Contains(selectedVO, vo.Name) {
			return vo.Auth.ProjectID
		}
	}
	return
}

// https://docs.openstack.org/api-ref/identity/v3/index.html#authentication-and-token-management
func (s *site) getScopedTokenInfo(ctx context.Context, auth *siteAuth, vo string) (parsedAuthResponse authResponse, scopedToken string, err error) {
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

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	var resp *http.Response
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return
	}

	scopedToken = resp.Header.Get("X-Subject-Token")

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

func (s *site) parseAuthResponse(auth *siteAuth, authResp authResponse, scopedToken string) (err error) {
	if auth == nil {
		err = fmt.Errorf("auth is nil")
		return
	}
	if authResp.Token == nil {
		err = fmt.Errorf("authResponse.Token is nil")
		return
	}
	auth.ScopedToken = scopedToken
	auth.TokenInfo = *authResp.Token
	for _, entry := range auth.TokenInfo.Catalog {
		if entry.Type == endpointType {
			auth.SwiftCatalogEntry = &entry
			for _, e := range entry.Endpoints {
				if e.Interface == "public" {
					auth.SwiftEndpoint = &e
					break
				}
			}
		}
	}
	return
}

func (s *site) authenticate(ua *userAuthParams) (err error) {
	ctx, cancel := context.WithTimeout(defaultCtx, defaultTimeout)
	defer cancel()

	// fmt.Printf("Authenticating against site %s\n", s)
	auth := new(siteAuth)
	auth.UnscopedToken, err = s.getUnscopedToken(ctx, ua.AccessToken)
	if err != nil {
		return
	}
	var (
		authResp    authResponse
		scopedToken string
	)
	authResp, scopedToken, err = s.getScopedTokenInfo(ctx, auth, ua.VO)
	if err != nil {
		return
	}

	err = s.parseAuthResponse(auth, authResp, scopedToken)
	if err != nil {
		return
	}

	s.Auth = auth
	return
}

func (s *site) isAuthenticated() bool {
	return s.Auth != nil && time.Until(*s.Auth.TokenInfo.ExpiresAt) > 0
}

func (s *site) getAuth(ua *userAuthParams) (auth *siteAuth, err error) {
	if s.isAuthenticated() {
		auth = s.Auth
		return
	}
	err = s.authenticate(ua)
	auth = s.Auth
	return
}

func (s *site) findPublicSwiftEndpoint(ua *userAuthParams) (ep *endpoint, err error) {
	auth, err := s.getAuth(ua)
	if err != nil {
		return
	}
	ep = auth.SwiftEndpoint
	return
}

func (s *site) hasAvailableSwiftEndpoint(ua *userAuthParams) bool {
	available := false
	for _, siteVO := range s.Config.VOs {
		if strings.Contains(ua.VO, siteVO.Name) {
			available = true
			break
		}
	}
	if !available {
		return false
	}

	ep, err := s.findPublicSwiftEndpoint(ua)
	if err != nil {
		printWarn("Failed to discover endpoint of site: " + s.String())
		return false
	}
	if ep == nil {
		return false
	}

	err = s.checkSwiftEndpoint(ep)
	if err != nil {
		printWarn("Swift endpoint is not operable at site: " + s.String())
		return false
	}
	return true
}

func (s *site) printRcloneEnvironment() (err error) {
	env := map[string]string{
		"OS_AUTH_TOKEN":  s.Auth.ScopedToken,
		"OS_AUTH_URL":    s.Config.Endpoint,
		"OS_STORAGE_URL": s.Auth.SwiftEndpoint.URL,
	}
	w := os.Stderr
	for k, v := range env {
		_, err = fmt.Fprintf(w, "export %s=%s\n", k, v)
		if err != nil {
			return
		}
	}
	return
}

func (s *site) checkSwiftEndpoint(endpoint *endpoint) (err error) {
	ctx, cancel := context.WithTimeout(defaultCtx, defaultTimeout)
	defer cancel()

	storageURL := endpoint.URL
	authToken := s.Auth.ScopedToken
	req, err := http.NewRequestWithContext(ctx, "GET", storageURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("X-Auth-Token", authToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("swift check failed: %v", resp.Status)
	}
	return
}

func getSite(c *config) (s *site, err error) {
	// if the user has provided an site argument we check it
	if *argSite != "" {
		s = c.GetSiteByName(*argSite)
		if s == nil {
			err = fmt.Errorf("no site with this name found: %s", *argSite)
			return
		}
		if !s.hasAvailableSwiftEndpoint(c.UserAuth) {
			err = fmt.Errorf("the selected site %s provides no public swift endpoint for the selected VO %s", *argSite, c.UserAuth.VO)
			return
		}
		err = printSelected("Site", s.String())
		return
	}

	sites := c.GetSwiftSitesForVO()
	siteCount := len(sites)
	if siteCount == 0 {
		err = fmt.Errorf("no sites provide swift for the selected VO")
		return
	}

	var siteName string
	if siteCount == 1 {
		siteName = sites[0]
		err = printSelected("Site", siteName)
		if err != nil {
			return
		}
	} else {
		fmt.Printf("Found %d sites providing swift\n", siteCount)
		siteName, err = selectString("Site", sites)
		if err != nil {
			return
		}
	}
	s = c.GetSiteByName(siteName)
	if s == nil {
		err = fmt.Errorf("invalid choice: '%s'", siteName)
	}
	return
}

func run() (err error) {
	config, err := newConfig()
	if err != nil {
		return
	}

	fmt.Printf("Searching sites providing swift for this VO\n")
	site, err := getSite(config)
	if err != nil {
		return
	}

	_, err = site.findPublicSwiftEndpoint(config.UserAuth)
	if err != nil {
		return
	}

	err = site.printRcloneEnvironment()
	if err != nil {
		return
	}

	var rcloneRemote string
	rcloneRemote, err = assureRcloneConfig()
	if err != nil {
		return
	}
	fmt.Printf("\nYou can now use the rclone remote %s like so:\n\t'rclone lsd %s:'\n", rcloneRemote, rcloneRemote)
	return
}

func registerInterruptHandler() {
	intChan := make(chan os.Signal, 1)
	signal.Notify(intChan, os.Interrupt)
	go func() {
		<-intChan
		fmt.Printf("\nExiting on user interrupt")
		defCancel()
		os.Exit(0)
	}()
}

func main() {
	registerInterruptHandler()
	if version != "" {
		kingpin.Version(version)
	}
	kingpin.Parse()

	err := run()
	if err != nil {
		printError("Error: " + err.Error())
	}
}
