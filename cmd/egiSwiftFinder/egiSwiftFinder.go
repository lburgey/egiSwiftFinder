package main

import (
	"fmt"
	"os"
	"os/signal"

	"github.com/lburgey/egiSwiftFinder/internal"
	"github.com/lburgey/egiSwiftFinder/internal/utils"

	"gopkg.in/alecthomas/kingpin.v2"
)

// version is set via: go build -ldflags '-X main.version=foobar'.
var version = ""

func registerInterruptHandler() {
	intChan := make(chan os.Signal, 1)
	signal.Notify(intChan, os.Interrupt)

	go func() {
		<-intChan
		fmt.Printf("\nExiting on user interrupt")
		internal.Cancel()
		os.Exit(0)
	}()
}

func main() {
	registerInterruptHandler()

	var (
		app                 = kingpin.New("source swift_finder", "A tool for discovering and using Openstack Swift endpoints provided by the EGI infrastructure.")
		argOIDCAgentAccount = app.Flag("oidc-agent", "oidc-agent account shortname").Short('o').Envar("OIDC_AGENT_ACCOUNT").String()
		argVO               = app.Flag("vo", "Virtual organisation").Short('v').Envar("EGI_VO").String()
		argSite             = app.Flag("site", "Site").Short('s').Envar("EGI_SITE").String()
	)

	app.UsageWriter(os.Stdout)

	if version != "" {
		app.Version(version)
	}

	kingpin.MustParse(app.Parse(os.Args[1:]))

	args := internal.Args{
		VO:               *argVO,
		Site:             *argSite,
		OIDCAgentAccount: *argOIDCAgentAccount,
	}

	err := internal.Run(&args)
	if err != nil {
		utils.PrintError("Error: " + err.Error())
	}
}
