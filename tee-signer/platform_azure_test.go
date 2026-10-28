//go:build platform_azure

package main

func init() { expectPlatforms = append(expectPlatforms, "azure") }
