package lab2

import (
	"errors"
	"fmt"
	"math"
	"math/big"
)

var (
	ErrNilInteger = errors.New("integer must not be nil")
	ErrNonPositiveMod = errors.New("modulus must be positive")
	ErrNotOddPositive = errors.New("value must be a positive odd integer")
	ErrNotPrimeModulus = errors.New("Legendre symbol modulus must be an odd prime")
	ErrFourierSizeLimit = errors.New("DFT Euler totient is limited to n <= 1000000")
)

type NumberTheory struct{}

type PrimePower struct {
	Prime *big.Int
	Exponent uint
}

func (NumberTheory) GCD(a, b *big.Int) (*big.Int, error) {
	if err := requireIntegers(a, b); err != nil {
		return nil, err
	}
	x, y := new(big.Int).Abs(new(big.Int).Set(a)), new(big.Int).Abs(new(big.Int).Set(b))
	for y.Sign() != 0 {
		x, y = y, new(big.Int).Mod(x, y)
	}
	return x, nil
}

type BezoutResult struct {
	GCD *big.Int
	X   *big.Int
	Y   *big.Int
}

func (NumberTheory) ExtendedGCD(a, b *big.Int) (BezoutResult, error) {
	if err := requireIntegers(a, b); err != nil {
		return BezoutResult{}, err
	}
	oldR, r := new(big.Int).Set(a), new(big.Int).Set(b)
	oldS, s := big.NewInt(1), big.NewInt(0)
	oldT, t := big.NewInt(0), big.NewInt(1)

	for r.Sign() != 0 {
		q := new(big.Int).Quo(oldR, r)
		oldR, r = r, new(big.Int).Sub(oldR, new(big.Int).Mul(q, r))
		oldS, s = s, new(big.Int).Sub(oldS, new(big.Int).Mul(q, s))
		oldT, t = t, new(big.Int).Sub(oldT, new(big.Int).Mul(q, t))
	}
	if oldR.Sign() < 0 {
		oldR.Neg(oldR)
		oldS.Neg(oldS)
		oldT.Neg(oldT)
	}
	return BezoutResult{GCD: oldR, X: oldS, Y: oldT}, nil
}

func (NumberTheory) BinaryGCD(a, b *big.Int) (*big.Int, error) {
	if err := requireIntegers(a, b); err != nil {
		return nil, err
	}
	u, v := new(big.Int).Abs(new(big.Int).Set(a)), new(big.Int).Abs(new(big.Int).Set(b))
	if u.Sign() == 0 {
		return v, nil
	}
	if v.Sign() == 0 {
		return u, nil
	}

	shift := uint(0)
	for u.Bit(0) == 0 && v.Bit(0) == 0 {
		u.Rsh(u, 1)
		v.Rsh(v, 1)
		shift++
	}
	for u.Bit(0) == 0 {
		u.Rsh(u, 1)
	}
	for v.Sign() != 0 {
		for v.Bit(0) == 0 {
			v.Rsh(v, 1)
		}
		if u.Cmp(v) > 0 {
			u, v = v, u
		}
		v.Sub(v, u)
	}
	return u.Lsh(u, shift), nil
}

func (NumberTheory) ModExp(base, exponent, modulus *big.Int) (*big.Int, error) {
	if err := requireIntegers(base, exponent, modulus); err != nil {
		return nil, err
	}
	if modulus.Sign() <= 0 {
		return nil, ErrNonPositiveMod
	}
	if exponent.Sign() < 0 {
		return nil, errors.New("exponent must be nonnegative")
	}
	if modulus.Cmp(big.NewInt(1)) == 0 {
		return big.NewInt(0), nil
	}

	result := big.NewInt(1)
	factor := new(big.Int).Mod(new(big.Int).Set(base), modulus)
	power := new(big.Int).Set(exponent)
	for power.Sign() > 0 {
		if power.Bit(0) == 1 {
			result.Mul(result, factor).Mod(result, modulus)
		}
		factor.Mul(factor, factor).Mod(factor, modulus)
		power.Rsh(power, 1)
	}
	return result, nil
}

func (nt NumberTheory) ModularInverse(value, modulus *big.Int) (*big.Int, error) {
	if err := requireIntegers(value, modulus); err != nil {
		return nil, err
	}
	if modulus.Sign() <= 0 {
		return nil, ErrNonPositiveMod
	}
	result, err := nt.ExtendedGCD(value, modulus)
	if err != nil {
		return nil, err
	}
	if result.GCD.Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("modular inverse does not exist")
	}
	return new(big.Int).Mod(result.X, modulus), nil
}

func (nt NumberTheory) LegendreSymbol(a, p *big.Int) (int, error) {
	if err := requireIntegers(a, p); err != nil {
		return 0, err
	}
	if p.Cmp(big.NewInt(2)) < 0 || p.Bit(0) == 0 {
		return 0, ErrNotPrimeModulus
	}
	// As in the mathematical definition, primality of p is a caller precondition.
	value := new(big.Int).Mod(new(big.Int).Set(a), p)
	if value.Sign() == 0 {
		return 0, nil
	}
	exponent := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	residue, err := nt.ModExp(value, exponent, p)
	if err != nil {
		return 0, err
	}
	if residue.Cmp(big.NewInt(1)) == 0 {
		return 1, nil
	}
	if residue.Cmp(new(big.Int).Sub(p, big.NewInt(1))) == 0 {
		return -1, nil
	}
	return 0, errors.New("Euler criterion returned a non-residue outside {1, -1}")
}

func (NumberTheory) JacobiSymbol(a, n *big.Int) (int, error) {
	if err := requireIntegers(a, n); err != nil {
		return 0, err
	}
	if n.Sign() <= 0 || n.Bit(0) == 0 {
		return 0, ErrNotOddPositive
	}

	x := new(big.Int).Mod(new(big.Int).Set(a), n)
	modulus := new(big.Int).Set(n)
	sign := 1
	for x.Sign() != 0 {
		for x.Bit(0) == 0 {
			x.Rsh(x, 1)
			remainder := new(big.Int).And(modulus, big.NewInt(7)).Int64()
			if remainder == 3 || remainder == 5 {
				sign = -sign
			}
		}
		x, modulus = modulus, x
		if x.Bit(1) == 1 && modulus.Bit(1) == 1 {
			sign = -sign
		}
		x.Mod(x, modulus)
	}
	if modulus.Cmp(big.NewInt(1)) == 0 {
		return sign, nil
	}
	return 0, nil
}

func (nt NumberTheory) Factorize(n *big.Int) ([]PrimePower, error) {
	if n == nil {
		return nil, ErrNilInteger
	}
	if n.Sign() <= 0 {
		return nil, errors.New("factorization is defined here only for positive integers")
	}
	remaining := new(big.Int).Set(n)
	factors := make([]PrimePower, 0)
	for _, prime := range []int64{2, 3, 5} {
		p := big.NewInt(prime)
		count := uint(0)
		for new(big.Int).Mod(remaining, p).Sign() == 0 {
			remaining.Quo(remaining, p)
			count++
		}
		if count > 0 {
			factors = append(factors, PrimePower{Prime: new(big.Int).Set(p), Exponent: count})
		}
	}

	for divisor := big.NewInt(7); new(big.Int).Mul(divisor, divisor).Cmp(remaining) <= 0; divisor.Add(divisor, big.NewInt(2)) {
		count := uint(0)
		for new(big.Int).Mod(remaining, divisor).Sign() == 0 {
			remaining.Quo(remaining, divisor)
			count++
		}
		if count > 0 {
			factors = append(factors, PrimePower{Prime: new(big.Int).Set(divisor), Exponent: count})
		}
	}
	if remaining.Cmp(big.NewInt(1)) > 0 {
		factors = append(factors, PrimePower{Prime: remaining, Exponent: 1})
	}
	return factors, nil
}

func (nt NumberTheory) EulerPhiByDefinition(n *big.Int) (*big.Int, error) {
	if n == nil {
		return nil, ErrNilInteger
	}
	if n.Sign() <= 0 {
		return nil, ErrNonPositiveMod
	}
	if !n.IsInt64() || n.Int64() > 1_000_000 {
		return nil, errors.New("definition-based Euler phi is limited to n <= 1000000")
	}
	count := int64(0)
	for k := int64(1); ; k++ {
		gcd, err := nt.GCD(big.NewInt(k), n)
		if err != nil {
			return nil, err
		}
		if gcd.Cmp(big.NewInt(1)) == 0 {
			count++
		}
		if big.NewInt(k).Cmp(n) == 0 {
			break
		}
	}
	return big.NewInt(count), nil
}

func (nt NumberTheory) EulerPhiByFactorization(n *big.Int) (*big.Int, error) {
	factors, err := nt.Factorize(n)
	if err != nil {
		return nil, err
	}
	result := new(big.Int).Set(n)
	for _, factor := range factors {
		result.Quo(result, factor.Prime)
		result.Mul(result, new(big.Int).Sub(factor.Prime, big.NewInt(1)))
	}
	return result, nil
}

// EulerPhiByDFT implements phi(n) = sum_{k=1}^n gcd(k,n) cos(2*pi*k/n).
// Floating-point work is explicitly bounded; the result is rounded to an integer.
func (nt NumberTheory) EulerPhiByDFT(n *big.Int) (*big.Int, error) {
	if n == nil {
		return nil, ErrNilInteger
	}
	if n.Sign() <= 0 {
		return nil, ErrNonPositiveMod
	}
	if !n.IsInt64() || n.Int64() > 1_000_000 {
		return nil, ErrFourierSizeLimit
	}
	size := n.Int64()
	if size == 1 {
		return big.NewInt(1), nil
	}

	sum, compensation := 0.0, 0.0
	for k := int64(1); k <= size; k++ {
		gcd, err := nt.GCD(big.NewInt(k), n)
		if err != nil {
			return nil, err
		}
		term := float64(gcd.Int64()) * math.Cos(2*math.Pi*float64(k)/float64(size))
		y := term - compensation
		t := sum + y
		compensation = (t - sum) - y
		sum = t
	}
	if math.IsNaN(sum) || math.IsInf(sum, 0) || math.Abs(sum) > float64(math.MaxInt64) {
		return nil, errors.New("DFT result is outside the supported integer range")
	}
	return big.NewInt(int64(math.Round(sum))), nil
}

func (nt NumberTheory) CarmichaelLambda(n *big.Int) (*big.Int, error) {
	factors, err := nt.Factorize(n)
	if err != nil {
		return nil, err
	}
	result := big.NewInt(1)
	for _, factor := range factors {
		var component *big.Int
		if factor.Prime.Cmp(big.NewInt(2)) == 0 {
			switch factor.Exponent {
			case 1:
				component = big.NewInt(1)
			case 2:
				component = big.NewInt(2)
			default:
				component = new(big.Int).Lsh(big.NewInt(1), factor.Exponent-2)
			}
		} else {
			power := integerPower(factor.Prime, factor.Exponent-1)
			component = power.Mul(power, new(big.Int).Sub(factor.Prime, big.NewInt(1)))
		}
		gcd, err := nt.GCD(result, component)
		if err != nil {
			return nil, err
		}
		result.Quo(result, gcd).Mul(result, component)
	}
	return result, nil
}

func integerPower(base *big.Int, exponent uint) *big.Int {
	result := big.NewInt(1)
	factor := new(big.Int).Set(base)
	for exponent > 0 {
		if exponent&1 == 1 {
			result.Mul(result, factor)
		}
		factor.Mul(factor, factor)
		exponent >>= 1
	}
	return result
}

func requireIntegers(values ...*big.Int) error {
	for i, value := range values {
		if value == nil {
			return fmt.Errorf("%w (argument %d)", ErrNilInteger, i+1)
		}
	}
	return nil
}
