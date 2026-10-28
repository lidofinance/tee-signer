package charonlock

import (
	"github.com/lidofinance/tee-signer/signer-protocol"
)

// Deposit and builder registration roots, as the deposit contract, the
// beacon chain and Charon compute them.

// DomainDeposit is DOMAIN_DEPOSIT.
var DomainDeposit = backend.DomainType{0x03, 0, 0, 0}

// WithdrawalCredentials are 0x01 (or 0x02 with compounding), 11 zero bytes
// and the address.
func WithdrawalCredentials(addr [20]byte, compounding bool) backend.Root {
	var wc backend.Root
	wc[0] = 0x01
	if compounding {
		wc[0] = 0x02
	}
	copy(wc[12:], addr[:])
	return wc
}

// DepositMessageRoot is hash_tree_root(DepositMessage).
func DepositMessageRoot(pk backend.Pubkey, wc backend.Root, amount uint64) backend.Root {
	return container(fixedBytes(pk[:]), wc, u64(amount))
}

// DepositSigningRoot is the root a deposit signature signs: under
// DOMAIN_DEPOSIT with the genesis fork version and a zero genesis validators
// root.
func DepositSigningRoot(pk backend.Pubkey, wc backend.Root, amount uint64, genesisFork backend.Version) backend.Root {
	return backend.SigningRoot(DepositMessageRoot(pk, wc, amount), backend.ComputeDomain(DomainDeposit, genesisFork, backend.Root{}))
}

// DepositDataRoot is hash_tree_root(DepositData), the deposit contract's
// deposit_data_root.
func DepositDataRoot(pk backend.Pubkey, wc backend.Root, amount uint64, sig backend.Signature) backend.Root {
	return container(fixedBytes(pk[:]), wc, u64(amount), fixedBytes(sig[:]))
}

// RegistrationSigningRoot is the root a builder registration signature
// signs: DOMAIN_APPLICATION_BUILDER with the genesis fork version and a zero
// genesis validators root.
func RegistrationSigningRoot(m *backend.ValidatorRegistration, genesisFork backend.Version) (backend.Root, error) {
	obj, err := backend.HashTreeRoot(m)
	if err != nil {
		return backend.Root{}, err
	}
	return backend.SigningRoot(obj, backend.ComputeDomain(backend.DomainApplicationBuilder, genesisFork, backend.Root{})), nil
}
