package lab2

import (
	"errors"
	"math/big"
)

type Convergent struct {
	K *big.Int
	D *big.Int
}

type WienerResult struct {
	Found       bool
	D           *big.Int
	Phi         *big.Int
	Convergents []Convergent
}

type WienerAttackService struct{}

func (WienerAttackService) Attack(publicKey RSAPublicKey) (WienerResult, error) {
	if publicKey.N == nil || publicKey.E == nil {
		return WienerResult{}, errors.New("RSA public key components must not be nil")
	}
	if publicKey.N.Cmp(big.NewInt(3)) < 0 || publicKey.N.Bit(0) == 0 ||
		publicKey.E.Cmp(big.NewInt(1)) <= 0 || publicKey.E.Cmp(publicKey.N) >= 0 {
		return WienerResult{}, errors.New("invalid RSA public key")
	}

	// Compute convergents of e/n by the continued-fraction recurrence.
	numerator := new(big.Int).Set(publicKey.E)
	denominator := new(big.Int).Set(publicKey.N)	
	pMinus2, pMinus1 := big.NewInt(0), big.NewInt(1)
	qMinus2, qMinus1 := big.NewInt(1), big.NewInt(0)
	result := WienerResult{Convergents: make([]Convergent, 0)}

	for denominator.Sign() != 0 {
		coefficient := new(big.Int).Quo(numerator, denominator)
		remainder := new(big.Int).Rem(numerator, denominator)

		k := new(big.Int).Add(new(big.Int).Mul(coefficient, pMinus1), pMinus2)
		d := new(big.Int).Add(new(big.Int).Mul(coefficient, qMinus1), qMinus2)
		if k.Sign() > 0 && d.Sign() > 0 {
			result.Convergents = append(result.Convergents, Convergent{
				K: new(big.Int).Set(k),
				D: new(big.Int).Set(d),
			})
			if phi, ok := validateWienerCandidate(publicKey, k, d); ok {
				result.Found = true
				result.D = new(big.Int).Set(d)
				result.Phi = phi
				return result, nil
			}
		}

		pMinus2, pMinus1 = pMinus1, k
		qMinus2, qMinus1 = qMinus1, d
		numerator, denominator = denominator, remainder
	}
	return result, nil
}

func validateWienerCandidate(publicKey RSAPublicKey, k, d *big.Int) (*big.Int, bool) {
	edMinusOne := new(big.Int).Sub(new(big.Int).Mul(publicKey.E, d), big.NewInt(1))
	phi, remainder := new(big.Int).QuoRem(edMinusOne, k, new(big.Int))
	if remainder.Sign() != 0 || phi.Sign() <= 0 {
		return nil, false
	}
	sum := new(big.Int).Add(new(big.Int).Sub(publicKey.N, phi), big.NewInt(1))
	discriminant := new(big.Int).Sub(new(big.Int).Mul(sum, sum), new(big.Int).Mul(big.NewInt(4), publicKey.N))
	if discriminant.Sign() < 0 {
		return nil, false
	}
	root := new(big.Int).Sqrt(discriminant)
	if new(big.Int).Mul(root, root).Cmp(discriminant) != 0 {
		return nil, false
	}
	if new(big.Int).Add(sum, root).Bit(0) != 0 {
		return nil, false
	}
	p := new(big.Int).Rsh(new(big.Int).Add(sum, root), 1)
	q := new(big.Int).Rsh(new(big.Int).Sub(sum, root), 1)
	if p.Cmp(big.NewInt(1)) <= 0 || q.Cmp(big.NewInt(1)) <= 0 {
		return nil, false
	}
	if new(big.Int).Mul(p, q).Cmp(publicKey.N) != 0 {
		return nil, false
	}
	actualPhi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)), new(big.Int).Sub(q, big.NewInt(1)))
	if actualPhi.Cmp(phi) != 0 {
		return nil, false
	}
	return phi, true
}
