package main

import (
	"fmt"
	"os"

	"github.com/adrg/xdg"
	"github.com/go-ini/ini"
)

func getRcloneConfig(fileName string) (cfg *ini.File, created bool, err error) {
	cfg, err = ini.Load(fileName)
	if err == nil {
		return
	}
	if os.IsNotExist(err) {
		fmt.Printf("No rclone config. Creating new config: %s\n", rcloneConfigFile)
		// make sure the directory for the config exists
		err = os.Mkdir(xdg.ConfigHome+"/rclone", os.ModePerm)
		if err != nil {
			return
		}
		created = true
		cfg = ini.Empty()
	}
	return
}

func searchSuitableRemote(cfg *ini.File) (remoteName string) {
	for _, section := range cfg.Sections() {
		if section.Key("type").String() == "swift" && section.Key("env_auth").MustBool() {
			remoteName = section.Name()
			fmt.Printf("Found suitable rclone remote: %s\n", remoteName)
			return
		}
	}
	fmt.Printf("No suitable rclone remote found\n")
	return
}

func addRemote(cfg *ini.File, remoteName string) (err error) {
	fmt.Printf("Adding remote to rclone config: %s\n", defaultRcloneRemoteName)
	var ns *ini.Section
	ns, err = cfg.NewSection(remoteName)
	if err != nil {
		return
	}
	_, err = ns.NewKey("type", "swift")
	if err != nil {
		return
	}
	_, err = ns.NewKey("env_auth", "true")
	if err != nil {
		return
	}
	return
}

// assureRcloneConfig makes sure there is a rclone config with a suitable remote
func assureRcloneConfig() (remoteName string, err error) {
	cfg, created, err := getRcloneConfig(rcloneConfigFile)
	if err != nil {
		return
	}
	if !created {
		remoteName = searchSuitableRemote(cfg)
		if remoteName != "" {
			return
		}
	}

	// add a suitable remote to the config
	remoteName = defaultRcloneRemoteName
	addRemote(cfg, remoteName)
	err = cfg.SaveTo(rcloneConfigFile)
	return
}
