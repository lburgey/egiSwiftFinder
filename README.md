# EGI Swift Finder
This tool can be used to discover and use Openstack Swift endpoints provided by the EGI infrastructure.

## Prerequisites
- Have rclone installed
- Have oidc-agent installed (see [here](https://indigo-dc.gitbook.io/oidc-agent/installation))
	- Configure the public client as explained [here](https://indigo-dc.gitbook.io/oidc-agent/user/oidc-gen/provider/egi)

## Installation and Usage
First download the latest release tarball from [here](https://github.com/lburgey/egiSwiftFinder/releases).

```bash
# Unpack the tarball contents somewhere your $PATH picks them up
tar xaf egiSwiftFinder-linux-amd64.tar.gz

# Execute and follow the instructions
# This will configure rclone and determine a VO and Site to use.
source swift_finder
```
