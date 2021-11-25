# EGI Swift Finder
This tool can be used to discover and use Openstack Swift endpoints provided by the EGI infrastructure.

## Prerequisites
- Have go installed
- Have rclone installed
- Have oidc-agent installed and configure the public client as explained [here](https://indigo-dc.gitbook.io/oidc-agent/user/oidc-gen/provider/egi)

## Installation and Usage
```bash
# Make sure that $GOPATH/bin or $GOBIN are part of your $PATH
go install github.com/lburgey/egiSwiftFinder@latest

# Download the wrapper script
wget https://raw.githubusercontent.com/lburgey/egiSwiftFinder/master/swift_finder

# Execute and follow the instructions
# This will configure rclone and determine a VO and Site to use.
source swift_finder
```
