package internal

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

var args = &Args{
	OIDCAgentAccount: os.Getenv("OIDC_AGENT_ACCOUNT"),
	Site:             os.Getenv("EGI_SITE"),
	VO:               os.Getenv("EGI_VO"),
}

func TestVOFromEntilements(t *testing.T) {
	assert.Equal(t, "eosc-synergy.eu", voFromEntitlement("urn:mace:egi.eu:group:eosc-synergy.eu:role=member#aai.egi.eu"))
	assert.Equal(t, "eosc-synergy.eu", voFromEntitlement("urn:mace:egi.eu:group:eosc-synergy.eu#aai.egi.eu"))
	assert.Equal(t, "eosc-synergy.eu", voFromEntitlement("urn:mace:egi.eu:group:eosc-synergy.eu:role=member"))
	assert.Equal(t, "eosc-synergy.eu", voFromEntitlement("urn:mace:egi.eu:group:eosc-synergy.eu:admins:role=owner#aai.egi.eu"))
}

func TestConfig(t *testing.T) {
	c := new(config)
	err := c.Fetch()
	assert.Nil(t, err)
	assert.Greater(t, len(c.Sites), 0)
}

func TestRun(t *testing.T) {
	err := Run(args)
	assert.Nil(t, err)
}

func TestCheckSwift(t *testing.T) {
	config, err := newConfig(args)
	assert.Nil(t, err)
	assert.NotNil(t, config)

	site, err := getSite(args, config)
	assert.Nil(t, err)
	assert.NotNil(t, site)

	endpoint, err := site.findPublicSwiftEndpoint(config.UserAuth)
	assert.Nil(t, err)
	assert.NotNil(t, endpoint)

	err = site.checkSwiftEndpoint(endpoint)
	assert.Nil(t, err)
}

func TestAssureRloneConfig(t *testing.T) {
	name, err := assureRcloneConfig()
	assert.Nil(t, err)
	assert.Equal(t, "egiswift", name)
}
