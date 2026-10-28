// Package relay carries the key generation messages between runners. It is
// not trusted: it sees only public messages (hellos, deals with sealed
// shares, results and confirmations), and every runner checks what it is
// given itself. Its own checks only stop a run early.
package relay

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"sync"

	"github.com/lidofinance/tee-signer/signer-protocol"
	"github.com/lidofinance/tee-signer/signer-protocol/dkgmsg"
)

// Runner is one participant, in share ID order. *remote.Client and
// *runnerclient.Client implement it.
type Runner interface {
	DKGHello(ctx context.Context, q *dkgmsg.HelloRequest) ([]byte, error)
	DKGDeal(ctx context.Context, hellos [][]byte) ([]byte, error)
	DKGFinish(ctx context.Context, deals [][]byte) (*dkgmsg.Finished, error)
	DKGCommit(ctx context.Context, q *dkgmsg.CommitRequest) ([]backend.ValidatorKey, error)
	DKGAbort(ctx context.Context) error
}

// Output is a finished run.
type Output struct {
	Result   *dkgmsg.Result           // runner 1's result (all results hash the same)
	Confirms []*dkgmsg.Confirm        // every runner's confirmation, in order
	Keys     [][]backend.ValidatorKey // keys each runner reports after the commit
}

// each runs f for every runner at once and returns the first error.
func each(n int, f func(i int) error) error {
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f(i); err != nil {
				errs[i] = fmt.Errorf("runner %d: %w", i+1, err)
			}
		}()
	}
	wg.Wait()
	return errors.Join(errs...)
}

// Options change a run.
type Options struct {
	// CheckHello, if set, checks runner i's hello before any runner deals
	// (PolicyCheck). A refusal aborts the run.
	CheckHello func(ctx context.Context, i int, hello []byte) error
}

// Run makes count validator keys among the runners. A failure before the
// commit round aborts the session on every runner.
func Run(ctx context.Context, runners []Runner, count int, opts Options) (*Output, error) {
	n := len(runners)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	abort := func(err error) (*Output, error) {
		_ = each(n, func(i int) error { return runners[i].DKGAbort(context.WithoutCancel(ctx)) })
		return nil, err
	}
	hellos := make([][]byte, n)
	q := &dkgmsg.HelloRequest{Nonce: nonce, Count: uint16(count)}
	if err := each(n, func(i int) (err error) { hellos[i], err = runners[i].DKGHello(ctx, q); return }); err != nil {
		return abort(fmt.Errorf("hello: %w", err))
	}
	if opts.CheckHello != nil {
		if err := each(n, func(i int) error { return opts.CheckHello(ctx, i, hellos[i]) }); err != nil {
			return abort(fmt.Errorf("hello check: %w", err))
		}
	}
	deals := make([][]byte, n)
	if err := each(n, func(i int) (err error) { deals[i], err = runners[i].DKGDeal(ctx, hellos); return }); err != nil {
		return abort(fmt.Errorf("deal: %w", err))
	}
	fins := make([]*dkgmsg.Finished, n)
	if err := each(n, func(i int) (err error) { fins[i], err = runners[i].DKGFinish(ctx, deals); return }); err != nil {
		return abort(fmt.Errorf("finish: %w", err))
	}
	out := &Output{Result: fins[0].Result, Keys: make([][]backend.ValidatorKey, n)}
	for i, f := range fins {
		if f.Result.Hash() != fins[0].Result.Hash() || f.Confirm.Signer != uint16(i+1) {
			return nil, fmt.Errorf("runner %d finished with another result", i+1)
		}
		out.Confirms = append(out.Confirms, f.Confirm)
	}
	cq := &dkgmsg.CommitRequest{Session: fins[0].Result.Session, Confirms: out.Confirms}
	if err := each(n, func(i int) (err error) { out.Keys[i], err = runners[i].DKGCommit(ctx, cq); return }); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return out, nil
}
