package main

// One runner binary per cloud. A binary holds the platforms it was built
// with and no others: each platform_*.go file, guarded by its build tag,
// registers one platform in init, and nothing else in this package imports
// a platform package. So the SDK and device code of a cloud (the AWS SDK,
// the Nitro NSM and vsock, the CBOR library, the Azure and Google code)
// reaches a binary only through its tag:
//
//	platform_dev    -platform dev     local tests, no hardware, protects nothing
//	platform_aws    -platform nitro   AWS Nitro Enclaves (also vsock and the S3 mark log)
//	platform_azure  -platform azure   Azure confidential containers (SEV-SNP)
//	platform_gcp    -platform gcp     Google Confidential Space
//
// scripts/build-runner.sh builds runner-aws, runner-azure, runner-gcp and
// runner-dev, and scripts/check-deps.sh checks that no cloud leaks into
// another one's binary. A binary built with none of the tags refuses to
// start.
//
// Each file also registers the platform's setup channel (-setup platform): the host agent over vsock on Nitro,
// SIGNER_SETUP on Azure and dev, the metadata attribute on GCP.

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/lidofinance/tee-signer/platform"
	"github.com/lidofinance/tee-signer/platform/setup"
)

type platformFunc func(platform.Options) (*platform.Platform, error)

// platforms is filled by the platform_*.go files of this build.
var platforms = map[string]platformFunc{}

// setupChannels holds each platform's setup channel, filled by the same
// files. A new channel is made for each start.
var setupChannels = map[string]func() setup.Channel{}

func registerSetup(name string, f func() setup.Channel) {
	if _, dup := setupChannels[name]; dup {
		panic("runner: setup channel of " + name + " registered twice")
	}
	setupChannels[name] = f
}

// platformTags names the build tag of each platform, for error messages.
var platformTags = map[string]string{
	"dev":   "platform_dev",
	"nitro": "platform_aws",
	"gcp":   "platform_gcp",
	"azure": "platform_azure",
}

func register(name string, f platformFunc) {
	if _, dup := platforms[name]; dup {
		panic("runner: platform " + name + " registered twice")
	}
	platforms[name] = f
}

// builtPlatforms lists the names of the platforms in this binary.
func builtPlatforms() []string {
	names := make([]string, 0, len(platforms))
	for n := range platforms {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// defaultPlatform is the platform when -platform is not given: the only one
// in the binary, else dev (the default before there was one binary per cloud).
func defaultPlatform() string {
	if names := builtPlatforms(); len(names) == 1 {
		return names[0]
	}
	return "dev"
}

var errNoPlatform = errors.New("this runner binary has no platform built in: build it with one platform tag " +
	"(-tags platform_aws, platform_azure, platform_gcp or platform_dev), as scripts/build-runner.sh does")

// lookupPlatform returns the constructor of the named platform, or says why
// this binary has none.
func lookupPlatform(name string) (platformFunc, error) {
	if len(platforms) == 0 {
		return nil, errNoPlatform
	}
	if f, ok := platforms[name]; ok {
		return f, nil
	}
	have := strings.Join(builtPlatforms(), ", ")
	if tag, known := platformTags[name]; known {
		return nil, fmt.Errorf("platform %q is not built into this binary (it has: %s); the build tag for %s is %s", name, have, name, tag)
	}
	return nil, fmt.Errorf("unknown platform %q (this binary has: %s)", name, have)
}
