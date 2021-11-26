package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVOFromEntilements(t *testing.T) {
	assert.Equal(t, "eosc-synergy.eu", voFromEntitlement("urn:mace:egi.eu:group:eosc-synergy.eu:role=member#aai.egi.eu"))
	assert.Equal(t, "eosc-synergy.eu", voFromEntitlement("urn:mace:egi.eu:group:eosc-synergy.eu#aai.egi.eu"))
	assert.Equal(t, "eosc-synergy.eu", voFromEntitlement("urn:mace:egi.eu:group:eosc-synergy.eu:role=member"))
	assert.Equal(t, "eosc-synergy.eu:admins", voFromEntitlement("urn:mace:egi.eu:group:eosc-synergy.eu:admins:role=owner#aai.egi.eu"))
}

func TestConfig(t *testing.T) {
	c := new(config)
	err := c.Fetch()
	assert.Nil(t, err)
	assert.Greater(t, len(c.Sites), 0)
}

func TestRun(t *testing.T) {
	*argOIDCAgentAccount = os.Getenv("OIDC_AGENT_ACCOUNT")
	*argSite = os.Getenv("EGI_SITE")
	*argVO = os.Getenv("EGI_VO")
	err := run()
	assert.Nil(t, err)
}

var benchmarkConfigResult *config

func BenchmarkConfig(b *testing.B) {
	c := new(config)
	for i := 0; i < b.N; i++ {
		c.Fetch()
	}
	benchmarkConfigResult = c
}

func TestAssureRloneConfig(t *testing.T) {
	name, err := assureRcloneConfig()
	assert.Nil(t, err)
	assert.Equal(t, "egiswift", name)
}
