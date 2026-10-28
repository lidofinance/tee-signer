//go:build platform_aws

package main

func init() { expectPlatforms = append(expectPlatforms, "nitro") }
