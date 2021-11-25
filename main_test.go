package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
