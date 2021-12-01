// Package internal contains internals for egiSwiftFinder
package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/indigo-dc/liboidcagent-go"
	"github.com/lburgey/egiSwiftFinder/internal/utils"
	"gopkg.in/yaml.v2"
)

const (
	defaultTimeout   = 3 * time.Second
	defaultConfigURL = "https://raw.githubusercontent.com/tdviet/fedcloudclient/master/config/sites.yaml"

	// endpointType which we search at the sites.
	endpointType            = "object-store"
	defaultRcloneRemoteName = "egiswift"
)

var (
	// voRegex is used for extracting the group part from entitlements.
	voRegex     = regexp.MustCompile("^(?:.+group:)(?P<vo>.+?)(?:(?:(?::admin)|:role=)|#)|$")
	Ctx, Cancel = context.WithCancel(context.Background())
)

type userInfo struct {
	Entitlements []string `json:"eduperson_entitlement"`
}

func voFromEntitlement(ent string) (vo string) {
	matches := voRegex.FindStringSubmatch(ent)
	if firstGroupIndex := 2; len(matches) == firstGroupIndex {
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
// Auth is populated in when successfully calling (*site).Authenticate().
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

// authResponse to calls to the /v3/auth/tokens endpoint.
type authResponse struct {
	Token *tokenInfo `json:"token"`
}

// tokenInfo binds *some* of the fields of the auth response.
// We don't need all the details here.
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
	ctx, cancel := context.WithTimeout(Ctx, defaultTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, "GET", defaultConfigURL, nil)
	if err != nil {
		return
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

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
	defer resp.Body.Close()

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

	return config, err
}

func (c *config) Fetch() (err error) {
	ctx, cancel := context.WithTimeout(Ctx, defaultTimeout)
	defer cancel()

	var configPaths []string

	configPaths, err = fetchConfigPaths()
	if err != nil {
		return
	}

	c.Sites = make([]*site, len(configPaths))

	waitgroup := sync.WaitGroup{}
	waitgroup.Add(len(configPaths))

	for siteIndex, path := range configPaths {
		c.Sites[siteIndex] = new(site)

		fetchSiteConfig := func(i int, path string) {
			var config *siteConfig

			config, err = fetchSiteConfig(ctx, path)
			if err == nil {
				c.Sites[i].Config = config
			} else {
				fmt.Printf("Failed to fetch config from %s\n", path)
			}

			waitgroup.Done()
		}
		go fetchSiteConfig(siteIndex, path)
	}

	waitgroup.Wait()

	return err
}

func newConfig(args *Args) (c *config, err error) {
	c = new(config)

	err = c.Fetch()
	if err != nil {
		return
	}

	err = c.SetUserAuth(args)

	return
}

func getOIDCAgentAccount(args *Args) (accountName string, err error) {
	if args.OIDCAgentAccount != "" {
		accountName = args.OIDCAgentAccount

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
		err = utils.PrintSelected("oidc-agent account", accountName)

		return
	}

	accountName, err = utils.SelectString("oidc-agent account", loadedAccounts)

	return
}

func (ua *userAuthParams) getAT(args *Args) (err error) {
	var accountName string

	accountName, err = getOIDCAgentAccount(args)
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

func (ua *userAuthParams) getUserInfo() (ui userInfo, err error) {
	ctx, cancel := context.WithTimeout(Ctx, defaultTimeout)
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

	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("user info request: %v - %s", resp.Status, bodyBytes)

		return
	}

	err = json.Unmarshal(bodyBytes, &ui)

	return ui, err
}

func (ua *userAuthParams) getVO(args *Args, userinfo userInfo) (err error) {
	if args.VO != "" {
		ua.VO = args.VO
		err = utils.PrintSelected("VO", ua.VO)

		return
	}

	vos := userinfo.getVOs()
	ua.VO, err = utils.SelectString("VO", vos)

	return
}

func (c *config) SetUserAuth(args *Args) (err error) {
	userAuth := new(userAuthParams)

	err = userAuth.getAT(args)
	if err != nil {
		return
	}

	var userinfo userInfo

	userinfo, err = userAuth.getUserInfo()
	if err != nil {
		return
	}

	err = userAuth.getVO(args, userinfo)
	if err != nil {
		return
	}

	c.UserAuth = userAuth

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

	waitgroup := sync.WaitGroup{}
	waitgroup.Add(len(c.Sites))

	go func() {
		for {
			swiftSite, ok := <-swiftSites
			if !ok {
				break
			}

			sites = append(sites, swiftSite)
		}
	}()

	for _, fetchSite := range c.Sites {
		go func(s *site) {
			if s.hasAvailableSwiftEndpoint(c.UserAuth) {
				swiftSites <- s.Config.Name
			}

			waitgroup.Done()
		}(fetchSite)
	}

	waitgroup.Wait()
	close(swiftSites)

	// original: 6.5s -> parallel ~1.2
	return sites
}

func (s *site) getUnscopedToken(ctx context.Context, userAuth *userAuthParams) (unscopedToken string, err error) {
	idp := "egi.eu"
	authProtocol := "openid"
	url := fmt.Sprintf("%s/OS-FEDERATION/identity_providers/%s/protocols/%s/auth",
		s.Config.Endpoint, idp, authProtocol)

	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return
	}

	req.Header.Set("Authorization", "Bearer "+userAuth.AccessToken)

	var resp *http.Response

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

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
	defer resp.Body.Close()

	scopedToken = resp.Header.Get("X-Subject-Token")

	var respBytes []byte

	respBytes, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return
	}

	err = json.Unmarshal(respBytes, &parsedAuthResponse)

	return parsedAuthResponse, scopedToken, err
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

	for i := range auth.TokenInfo.Catalog {
		entry := &auth.TokenInfo.Catalog[i]
		if entry.Type == endpointType {
			auth.SwiftCatalogEntry = entry

			for i := range entry.Endpoints {
				endpoint := &entry.Endpoints[i]

				if endpoint.Interface == "public" {
					auth.SwiftEndpoint = endpoint

					break
				}
			}
		}
	}

	return err
}

func (s *site) authenticate(userAuth *userAuthParams) (err error) {
	ctx, cancel := context.WithTimeout(Ctx, defaultTimeout)
	defer cancel()

	// fmt.Printf("Authenticating against site %s\n", s)
	auth := new(siteAuth)

	auth.UnscopedToken, err = s.getUnscopedToken(ctx, userAuth)
	if err != nil {
		return
	}

	var (
		authResp    authResponse
		scopedToken string
	)

	authResp, scopedToken, err = s.getScopedTokenInfo(ctx, auth, userAuth.VO)
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

func (s *site) getAuth(userAuth *userAuthParams) (auth *siteAuth, err error) {
	if s.isAuthenticated() {
		auth = s.Auth

		return
	}

	err = s.authenticate(userAuth)
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

func (s *site) hasAvailableSwiftEndpoint(userAuth *userAuthParams) bool {
	available := false

	for _, siteVO := range s.Config.VOs {
		if strings.Contains(userAuth.VO, siteVO.Name) {
			available = true

			break
		}
	}

	if !available {
		return false
	}

	endpoint, err := s.findPublicSwiftEndpoint(userAuth)
	if err != nil {
		utils.PrintWarn("Failed to discover endpoint of site: " + s.String())

		return false
	} else if endpoint == nil {
		return false
	}

	err = s.checkSwiftEndpoint(endpoint)
	if err != nil {
		utils.PrintWarn("Swift endpoint is not operable at site: " + s.String())

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
	ctx, cancel := context.WithTimeout(Ctx, defaultTimeout)
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
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("swift check failed: %v", resp.Status)
	}

	return
}

func getSite(args *Args, conf *config) (s *site, err error) {
	// If the user has provided an site argument we check it.
	if args.Site != "" {
		s = conf.GetSiteByName(args.Site)
		if s == nil {
			err = fmt.Errorf("no site with this name found: %s", args.Site)

			return
		}

		if !s.hasAvailableSwiftEndpoint(conf.UserAuth) {
			err = fmt.Errorf("the selected site %s provides no public swift endpoint for the selected VO %s", args.Site, conf.UserAuth.VO)

			return
		}

		err = utils.PrintSelected("Site", s.String())

		return
	}

	sites := conf.GetSwiftSitesForVO()

	siteCount := len(sites)
	if siteCount == 0 {
		err = fmt.Errorf("no sites provide swift for the selected VO")

		return
	}

	var siteName string
	if siteCount == 1 {
		siteName = sites[0]

		err = utils.PrintSelected("Site", siteName)
		if err != nil {
			return
		}
	} else {
		fmt.Printf("  Found %d sites providing swift\n", siteCount)
		siteName, err = utils.SelectString("Site", sites)
		if err != nil {
			return
		}
	}

	s = conf.GetSiteByName(siteName)
	if s == nil {
		err = fmt.Errorf("invalid choice: '%s'", siteName)
	}

	return s, err
}

// Args are optional user provided arguments.
type Args struct {
	VO               string
	OIDCAgentAccount string
	Site             string
}

func Run(args *Args) (err error) {
	config, err := newConfig(args)
	if err != nil {
		return
	}

	fmt.Printf("  Searching sites providing swift for this VO\n")

	site, err := getSite(args, config)
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

	expiresAt := *site.Auth.TokenInfo.ExpiresAt
	if !expiresAt.IsZero() {
		timeToTokenExpiry := time.Until(expiresAt).Truncate(time.Second)
		utils.PrintWarn(fmt.Sprintf("Token expires in: %s", timeToTokenExpiry))
		fmt.Print("\tYou have to rerun this tool after the token expired.")
	}

	fmt.Printf("\n%s You can now use the rclone remote %s using e.g.:\n\t'rclone lsd %s:'\n", utils.IconGood, rcloneRemote, rcloneRemote)

	return err
}
