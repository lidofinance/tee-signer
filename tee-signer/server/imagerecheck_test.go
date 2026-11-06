//go:build !debugimport

package server

import (
	"testing"

	"github.com/lidofinance/tee-signer/governance/setupwire"
	"github.com/lidofinance/tee-signer/signer-protocol"
	wireadmin "github.com/lidofinance/tee-signer/signer-protocol/wire/admin"
)

// SETUP-IMAGE-01: a SIGN that passed dispatch's image check and then
// waited past an update that drops this image signs nothing.
func TestImageRecheckedBeforeSign(t *testing.T) {
	mine, other := testImage(setupwire.ImageAzure, 0x11), testImage(setupwire.ImageAzure, 0x22)
	e := gatedEnv(t, u64(0), "azure", mine, other, mine)
	if err := e.signWire(); err != nil {
		t.Fatalf("listed image: %v", err)
	}
	b := e.body(locked, 1, e.groupHash(locked), e.now())
	b.Locked.AllowedImageMeasurements = imageList(other)
	e.mustSend(signed(t, b, first2, nil), wireadmin.ConfigAccepted)

	m := &backend.ValidatorRegistration{FeeRecipient: e.setup.Locked.AllowedFeeRecipients[0], GasLimit: 36_000_000, Timestamp: e.now() + 1, Pubkey: e.pk}
	cfg := e.signer.Config()
	d, err := cfg.MessageDomain(m)
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.srv.sign(backend.SignRequest{Pubkey: e.pk, Message: m, Domain: d})
	wantCode(t, err, backend.StatusNotReady, "locked version 1")
}

// SETUP-IMAGE-01: a sealed import, single or batch, that passed
// dispatch's image check stores no share once the image is not allowed.
func TestImageRecheckedBeforeImport(t *testing.T) {
	e := newTgtEnv(t, "dev", nil)
	g, err := NewImageGate(ctx, ImageGateOptions{Platform: "gcp", SelfImage: selfIs(testImage(setupwire.ImageGCP, 0x5e)), Log: quiet})
	if err != nil {
		t.Fatal(err)
	}

	sk, pk := newKey(t)
	e.srv.Image = g
	_, err = e.srv.addShare(pk, &sk, 5, nil, "sealed")
	wantCode(t, err, backend.StatusNotReady, "image check")
	sks, pks := batchKeys(t, 3)
	_, err = e.srv.importBatch(e.batchPayload(sks, pks, nil))
	wantCode(t, err, backend.StatusNotReady, "image check")
	for _, k := range append(pks, pk) {
		if n := e.store.putsOf(shareKey(k)); n != 0 {
			t.Fatalf("%s: %d share writes after the image check refused", k.String()[:18], n)
		}
	}
	e.wantLoaded("refused", append(pks, pk), false)

	// The same imports without the gate go through.
	e.srv.Image = nil
	if _, err := e.srv.addShare(pk, &sk, 5, nil, "sealed"); err != nil {
		t.Fatal(err)
	}
	if _, err := e.srv.importBatch(e.batchPayload(sks, pks, nil)); err != nil {
		t.Fatal(err)
	}
	e.wantLoaded("accepted", append(pks, pk), true)
}
