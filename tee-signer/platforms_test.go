package main

import (
	"sort"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/platform"
)

// expectPlatforms is filled by the platform_*_test.go files: the platforms
// this test binary was built with tags for.
var expectPlatforms []string

// withPlatforms runs f with a registry that holds exactly the named platforms.
func withPlatforms(names []string, f func()) {
	saved := platforms
	platforms = map[string]platformFunc{}
	defer func() { platforms = saved }()
	for _, n := range names {
		register(n, func(platform.Options) (*platform.Platform, error) { return &platform.Platform{Name: n}, nil })
	}
	f()
}

func TestRegisteredPlatformsFollowTheTags(t *testing.T) {
	want := append([]string{}, expectPlatforms...)
	sort.Strings(want)
	got := builtPlatforms()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("this build registers %v, its tags say %v", got, want)
	}
}

func TestNoPlatformRefusesToStart(t *testing.T) {
	withPlatforms(nil, func() {
		if err := run(); err != errNoPlatform {
			t.Fatalf("run with no platform: %v", err)
		}
		_, err := lookupPlatform("dev")
		if err != errNoPlatform {
			t.Fatalf("lookup with no platform: %v", err)
		}
		for _, tag := range []string{"platform_aws", "platform_azure", "platform_gcp", "platform_dev"} {
			if !strings.Contains(err.Error(), tag) {
				t.Fatalf("the error does not name %s: %v", tag, err)
			}
		}
		if defaultPlatform() != "dev" {
			t.Fatalf("default platform %q", defaultPlatform())
		}
	})
}

func TestOneCloudBinary(t *testing.T) {
	withPlatforms([]string{"azure"}, func() {
		if f, err := lookupPlatform("azure"); err != nil || f == nil {
			t.Fatalf("azure in an azure build: %v", err)
		}
		_, err := lookupPlatform("nitro")
		if err == nil || !strings.Contains(err.Error(), `platform "nitro" is not built into this binary (it has: azure)`) ||
			!strings.Contains(err.Error(), "platform_aws") {
			t.Fatalf("nitro in an azure build: %v", err)
		}
		if _, err = lookupPlatform("dev"); err == nil || !strings.Contains(err.Error(), "platform_dev") {
			t.Fatalf("dev in an azure build: %v", err)
		}
		if _, err = lookupPlatform("bogus"); err == nil || !strings.Contains(err.Error(), `unknown platform "bogus" (this binary has: azure)`) {
			t.Fatalf("an unknown platform: %v", err)
		}
		if defaultPlatform() != "azure" {
			t.Fatalf("the only platform is not the default: %q", defaultPlatform())
		}
	})
}

func TestTwoPlatformBinary(t *testing.T) {
	withPlatforms([]string{"nitro", "dev"}, func() {
		if got := strings.Join(builtPlatforms(), ","); got != "dev,nitro" {
			t.Fatalf("platforms %q", got)
		}
		if defaultPlatform() != "dev" {
			t.Fatalf("default platform %q", defaultPlatform())
		}
	})
}

func TestRegisteringTwiceIsABug(t *testing.T) {
	withPlatforms([]string{"gcp"}, func() {
		defer func() {
			if recover() == nil {
				t.Fatal("a second registration of gcp did not panic")
			}
		}()
		register("gcp", nil)
	})
}
