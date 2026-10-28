package server

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/buildflavor"
	"github.com/lidofinance/tee-signer/signer-protocol/wire"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// testImage is an image of kind k whose measurement is fill repeated.
func testImage(k setupwire.ImageKind, fill byte) setupwire.Image {
	return setupwire.Image{Kind: k, Measurement: bytes.Repeat([]byte{fill}, k.Size())}
}

// imageList is ims sorted as setupwire wants them.
func imageList(ims ...setupwire.Image) []setupwire.Image {
	out := slices.Clone(ims)
	slices.SortFunc(out, func(a, b setupwire.Image) int {
		if a.Kind != b.Kind {
			return int(a.Kind) - int(b.Kind)
		}
		return bytes.Compare(a.Measurement, b.Measurement)
	})
	return out
}

// selfIs is a SelfImage hook that names im, as a platform's key release
// evidence would.
func selfIs(im setupwire.Image) func(context.Context) (setupwire.Image, error) {
	return func(context.Context) (setupwire.Image, error) { return im, nil }
}

// gatedEnv is newEnv whose setup lists images, with an image check of a
// runner on platform plat whose own image self is.
func gatedEnv(t *testing.T, lock *uint64, plat string, self setupwire.Image, listed ...setupwire.Image) *env {
	t.Helper()
	e := newEnvWith(t, lock, func(s *setupwire.Setup) { s.Locked.AllowedImageMeasurements = imageList(listed...) })
	g, err := NewImageGate(ctx, ImageGateOptions{Platform: plat, SelfImage: selfIs(self), Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Image = g
	return e
}

// signWire sends a builder registration as SIGN through dispatch, the path
// a client's request takes.
func (e *env) signWire() error {
	e.t.Helper()
	m := &backend.ValidatorRegistration{FeeRecipient: e.setup.Locked.AllowedFeeRecipients[0], GasLimit: 36_000_000, Timestamp: e.now(), Pubkey: e.pk}
	cfg := e.signer.Config()
	d, err := cfg.MessageDomain(m)
	if err != nil {
		e.t.Fatal(err)
	}
	p, err := wire.EncodeSign(backend.SignRequest{Pubkey: e.pk, Message: m, Domain: d})
	if err != nil {
		e.t.Fatal(err)
	}
	_, err = e.srv.dispatch(ctx, wire.Frame{Type: wire.TypeSign, Payload: p})
	return err
}

// imageState is HEALTH's image check and readiness.
func (e *env) imageState() (*backend.ImageCheck, bool) {
	e.t.Helper()
	h, err := e.srv.health()
	if err != nil {
		e.t.Fatal(err)
	}
	if h.Image == nil {
		e.t.Fatal("HEALTH carries no image check")
	}
	return h.Image, h.Ready
}

func wantImageState(t *testing.T, e *env, state string, ready bool) {
	t.Helper()
	c, r := e.imageState()
	if c.State != state || r != ready {
		t.Fatalf("HEALTH image %+v, ready %v; want state %s, ready %v", c, r, state, ready)
	}
}

// On every platform kind, an image on the allowed list in force signs and
// one that is not signs nothing: SIGN gets NOT_READY, HEALTH says
// not_allowed and not ready. The list naming another platform's image with
// the same bytes does not count.
func TestImageCheckMatchAndMismatchPerPlatform(t *testing.T) {
	for _, c := range []struct {
		plat string
		kind setupwire.ImageKind
	}{{"nitro", setupwire.ImageNitro}, {"azure", setupwire.ImageAzure}, {"gcp", setupwire.ImageGCP}} {
		t.Run(c.plat, func(t *testing.T) {
			mine, other := testImage(c.kind, 0xa1), testImage(c.kind, 0xb2)
			e := gatedEnv(t, nil, c.plat, mine, other, mine)
			if err := e.signWire(); err != nil {
				t.Fatalf("listed image: %v", err)
			}
			wantImageState(t, e, backend.ImageAllowed, true)
			if st, _ := e.imageState(); st.Kind != c.plat || st.LockedVersion != 0 || len(st.Measurement) != 2*c.kind.Size() {
				t.Fatalf("HEALTH image %+v", st)
			}

			// Another image of the same platform, and the same bytes under
			// another kind, are not this image.
			var foreign setupwire.Image
			if c.kind == setupwire.ImageNitro {
				foreign = testImage(setupwire.ImageGCP, 0xa1)
			} else {
				foreign = testImage(setupwire.ImageNitro, 0xa1)
			}
			e = gatedEnv(t, nil, c.plat, mine, other, foreign)
			wantCode(t, e.signWire(), backend.StatusNotReady, "is not on allowed_image_measurements of locked version 0")
			wantImageState(t, e, backend.ImageNotAllowed, false)
		})
	}
}

// What an image the list does not name still answers: HEALTH, PUBLIC_KEYS,
// IDENTITY and CONFIG_UPDATE. Everything that signs, hands over or imports
// gets NOT_READY before its own checks run.
func TestImageCheckRefusesAllButStatusAndConfig(t *testing.T) {
	e := gatedEnv(t, nil, "gcp", testImage(setupwire.ImageGCP, 1), testImage(setupwire.ImageGCP, 2))
	nonce, _ := wire.EncodeAttest(bytes.Repeat([]byte{7}, 32))
	for _, typ := range []wire.MsgType{wire.TypeHealth, wire.TypePublicKeys, wire.TypeIdentity} {
		p := []byte(nil)
		if typ == wire.TypeIdentity {
			p = nonce
		}
		if _, err := e.srv.dispatch(ctx, wire.Frame{Type: typ, Payload: p}); err != nil {
			t.Fatalf("%v: %v", typ, err)
		}
	}
	for _, typ := range []wire.MsgType{wire.TypeSign, wireadmin.TypeImportSealed, wireadmin.TypeApproveExit, 0x30, 0x31, 0x32, 0x33, 0x27, 0x28} {
		_, err := e.srv.dispatch(ctx, wire.Frame{Type: typ, Payload: []byte{1, 2, 3}})
		wantCode(t, err, backend.StatusNotReady, "image check:")
	}
	// CONFIG_UPDATE gets through: the approvers' way to list the image.
	b := e.body(locked, 1, e.groupHash(locked), e.now())
	b.Locked.AllowedFeeRecipients = append(b.Locked.AllowedFeeRecipients, x)
	e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted)
}

// A locked update that adds this image is pending for the images minimum:
// the runner keeps refusing until the update's effective time, then signs
// without a restart. A later update that drops the image stops it at that
// update's effective time.
func TestImageCheckFollowsLockedUpdates(t *testing.T) {
	mine, other := testImage(setupwire.ImageAzure, 0x11), testImage(setupwire.ImageAzure, 0x22)
	e := gatedEnv(t, u64(0), "azure", mine, other)
	wantCode(t, e.signWire(), backend.StatusNotReady, "locked version 0")

	t0 := e.now()
	b1 := e.body(locked, 1, e.groupHash(locked), t0)
	b1.Locked.AllowedImageMeasurements = imageList(other, mine)
	h1 := hashOf(t, b1)
	st := e.mustSend(signed(t, b1, first2, nil), wireadmin.ConfigAccepted)
	wait := uint64(setupwire.ImagesMinTimeLock)
	if st.Locked.Pending != pending(1, h1, t0+wait) {
		t.Fatalf("the update that adds an image waits the images minimum: %+v", st.Locked)
	}
	// Pending, not yet in force: still refused, HEALTH still on version 0.
	e.clock.add(wait - 1)
	wantCode(t, e.signWire(), backend.StatusNotReady, "locked version 0")
	if c, _ := e.imageState(); c.State != backend.ImageNotAllowed || c.LockedVersion != 0 {
		t.Fatalf("before the effective time: %+v", c)
	}
	// In force at arrival + wait, before any record says so.
	e.clock.add(1)
	if err := e.signWire(); err != nil {
		t.Fatalf("at the effective time: %v", err)
	}
	if c, ready := e.imageState(); c.State != backend.ImageAllowed || c.LockedVersion != 1 || !ready {
		t.Fatalf("after the effective time: %+v, ready %v", c, ready)
	}
	if logPending(t, e, locked) == nil {
		t.Fatal("a record shows the update active before Sync wrote one")
	}

	// Dropping the image: version 2 lists other only. Its wait is the
	// change delay (0); no image is gained.
	b2 := e.body(locked, 2, h1, e.now())
	b2.Locked.AllowedImageMeasurements = imageList(other)
	e.mustSend(signed(t, b2, first2, nil), wireadmin.ConfigAccepted)
	wantCode(t, e.signWire(), backend.StatusNotReady, "locked version 2")
	wantImageState(t, e, backend.ImageNotAllowed, false)
}

// A runner whose start found its image not allowed keeps its shares sealed
// (Withhold). Once the list names the image it still refuses, and says to
// restart, so no share enters the core without a fresh start.
func TestImageCheckWithheldNeedsRestart(t *testing.T) {
	mine := testImage(setupwire.ImageGCP, 0x31)
	e := gatedEnv(t, u64(0), "gcp", mine)
	if e.srv.Image.Check(e.upd) == nil {
		t.Fatal("an image off the list passed")
	}
	e.srv.Image.Withhold()
	b := e.body(locked, 1, e.groupHash(locked), e.now())
	b.Locked.AllowedImageMeasurements = imageList(mine)
	e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted)
	e.clock.add(uint64(setupwire.ImagesMinTimeLock))
	wantCode(t, e.signWire(), backend.StatusNotReady, "restart the runner")
	wantImageState(t, e, backend.ImageRestartNeeded, false)
}

// A cloud platform that cannot name its own image refuses (state unknown);
// so does one with no SelfImage hook at all. The dev platform has no image
// kind: the check does not apply there. A runner without a setup (nil
// Updates) has no list.
func TestImageCheckUnknownAndNotApplicable(t *testing.T) {
	e := gatedEnv(t, nil, "gcp", testImage(setupwire.ImageGCP, 1), testImage(setupwire.ImageGCP, 1))
	bad := errors.New("the key release evidence names no image: no image_digest")
	for _, o := range []ImageGateOptions{
		{Platform: "gcp", SelfImage: func(context.Context) (setupwire.Image, error) { return setupwire.Image{}, bad }},
		{Platform: "nitro"},
	} {
		g, err := NewImageGate(ctx, o)
		if err != nil {
			t.Fatal(err)
		}
		g.log = quiet
		e.srv.Image = g
		wantCode(t, e.signWire(), backend.StatusNotReady, "cannot tell its own image")
		wantImageState(t, e, backend.ImageUnknown, false)
	}
	g, err := NewImageGate(ctx, ImageGateOptions{Platform: "dev", Log: quiet})
	if err != nil {
		t.Fatal(err)
	}
	e.srv.Image = g
	if err := e.signWire(); err != nil {
		t.Fatalf("dev: %v", err)
	}
	wantImageState(t, e, backend.ImageNotApplicable, true)
	g, _ = NewImageGate(ctx, ImageGateOptions{Platform: "gcp", SelfImage: selfIs(testImage(setupwire.ImageGCP, 9)), Log: quiet})
	if err := g.Check(nil); err != nil {
		t.Fatalf("no setup: %v", err)
	}
}

// Release gate: a default build has no override. NewImageGate refuses one,
// so no code path of a default build serves an image the list does not
// name. The testnet build's override is tested in imagegate_testnet_test.go.
func TestImageCheckDefaultBuildHasNoOverride(t *testing.T) {
	if buildflavor.Name != "default" {
		t.Skip("default build only")
	}
	_, err := NewImageGate(ctx, ImageGateOptions{Platform: "gcp", SelfImage: selfIs(testImage(setupwire.ImageGCP, 1)), Override: true, Log: quiet})
	if !errors.Is(err, ErrOverrideInDefaultBuild) {
		t.Fatalf("override in a default build: %v", err)
	}
	if !strings.Contains(err.Error(), "only a testnet build") {
		t.Fatalf("unclear refusal: %v", err)
	}
}
