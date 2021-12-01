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
tar xaf egiSwiftFinder-<linux|darwin>-amd64.tar.gz

# Execute and follow the instructions
# This will configure rclone and determine a VO and Site to use.
source swift_finder
```

If you want want to repeatedly use the same swift endpoint, you can set defaults using environment variables:
```bash
export OIDC_AGENT_ACCOUNT=<account shortname>
export EGI_SITE=<site name>
export EGI_VO=<vo name>

# this call should not prompt you
source swift_finder
```

Alternatively, flags can be passed to the tool. See the help:
```bash
source swift_finder --help
```

## How does all of this work?
rclone is configured to read parameters regarding the swift endpoint from environment variables.
The relevant variables are: `OS_STORAGE_URL`, `OS_AUTH_URL` and `OS_AUTH_TOKEN`.

By using `source` to call the swift finder, the environment variables are applied to the current shells environment.
Subsequent calls to rclone in the same shell can then use the environment variables.
