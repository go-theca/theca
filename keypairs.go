package theca

import (
	"context"
	"fmt"
)

// KeyPairs asks the key ONCE (one touch) for the pairs it forms with the
// partner factors: for every partner and every Theca credential the key
// holds, the factor set {partner, key}, which is what opens a key slot. They
// are what RemoveFactorSets and SlotsOf take to remove a key slot, or to
// prove, before a removal, that the key still opens the container.
//
// The pairs are ordered by credential, then by partner. A key holding no Theca
// credential is ErrNoCredential: there is nothing to prove with. The caller
// wipes the pairs with WipeSets (they hold copies of the partners' keys).
func KeyPairs(ctx context.Context, dev FIDO2, partners ...Factor) ([][]Factor, error) {
	if len(partners) == 0 || len(partners) > MaxFIDO2Salts {
		return nil, fmt.Errorf("%w: a key pairs with 1 or %d partner factors, not %d", ErrOption, MaxFIDO2Salts, len(partners))
	}
	salts := fido2Salts(partners) // password-equivalent: wiped, never logged
	defer clearSalts(salts)
	creds, err := dev.Derive(ctx, salts)
	defer func() {
		for _, cr := range creds {
			for _, o := range cr {
				clear(o)
			}
		}
	}()
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return nil, ErrNoCredential
	}
	if len(creds) > MaxFIDO2Credentials {
		return nil, fmt.Errorf("%w: %d credentials (at most %d)", ErrAuthenticator, len(creds), MaxFIDO2Credentials)
	}
	var out [][]Factor
	for _, outs := range creds {
		if err := checkOutputs(outs, len(partners)); err != nil {
			WipeSets(out)
			return nil, err
		}
		for j := range partners {
			out = append(out, []Factor{partners[j], FIDO2Factor(outs[j])})
		}
	}
	return out, nil
}

// WipeSets zeroes every factor of every set.
func WipeSets(sets [][]Factor) {
	for _, fs := range sets {
		for i := range fs {
			fs[i].Zeroize()
		}
	}
}
