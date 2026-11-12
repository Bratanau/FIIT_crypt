package lab2

import (
	"crypto/rand"
	"errors"
	"io"
	"math"
	"math/big"
)

type PrimalityTest interface {
	Test(n *big.Int, minimumConfidence float64) (bool, error)
}

type IterationHook func(n, randomBase *big.Int) (bool, error)

type PrimalityKind uint8

const (
	Fermat PrimalityKind = iota + 1
	SolovayStrassen
	MillerRabin
)

// ProbabilisticTestBase implements the template method. Concrete tests supply
// only oneRound; candidate handling and confidence-to-round conversion remain
// common.
type ProbabilisticTestBase struct {
	oneRound     IterationHook
	errorBound   float64
	randomSource io.Reader
}

func NewProbabilisticTestBase(oneRound IterationHook, singleRoundErrorBound float64) (*ProbabilisticTestBase, error) {
	if oneRound == nil {
		return nil, errors.New("one-round test hook must not be nil")
	}
	if singleRoundErrorBound <= 0 || singleRoundErrorBound >= 1 || math.IsNaN(singleRoundErrorBound) {
		return nil, errors.New("single-round error bound must be strictly between 0 and 1")
	}
	return &ProbabilisticTestBase{
		oneRound:     oneRound,
		errorBound:   singleRoundErrorBound,
		randomSource: rand.Reader,
	}, nil
}

func (test *ProbabilisticTestBase) Test(n *big.Int, minimumConfidence float64) (bool, error) {
	if n == nil {
		return false, ErrNilInteger
	}
	if minimumConfidence < 0.5 || minimumConfidence >= 1 || math.IsNaN(minimumConfidence) {
		return false, errors.New("minimum confidence must be in [0.5, 1)")
	}
	if n.Cmp(big.NewInt(2)) < 0 {
		return false, nil
	}
	if n.Cmp(big.NewInt(2)) == 0 || n.Cmp(big.NewInt(3)) == 0 {
		return true, nil
	}
	if n.Bit(0) == 0 {
		return false, nil
	}

	rounds := int(math.Ceil(math.Log1p(-minimumConfidence) / math.Log(test.errorBound)))
	if rounds < 1 {
		rounds = 1
	}
	upper := new(big.Int).Sub(n, big.NewInt(3))
	for i := 0; i < rounds; i++ {
		base, err := rand.Int(test.randomSource, upper)
		if err != nil {
			return false, err
		}
		base.Add(base, big.NewInt(2))
		pass, err := test.oneRound(n, base)
		if err != nil {
			return false, err
		}
		if !pass {
			return false, nil
		}
	}
	return true, nil
}

type FermatTest struct{ *ProbabilisticTestBase }

func NewFermatTest() (*FermatTest, error) {
	base, err := NewProbabilisticTestBase(fermatRound, 0.5)
	if err != nil {
		return nil, err
	}
	return &FermatTest{base}, nil
}

func fermatRound(n, a *big.Int) (bool, error) {
	nt := NumberTheory{}
	exponent := new(big.Int).Sub(n, big.NewInt(1))
	value, err := nt.ModExp(a, exponent, n)
	if err != nil {
		return false, err
	}
	return value.Cmp(big.NewInt(1)) == 0, nil
}

type SolovayStrassenTest struct{ *ProbabilisticTestBase }

func NewSolovayStrassenTest() (*SolovayStrassenTest, error) {
	base, err := NewProbabilisticTestBase(solovayStrassenRound, 0.5)
	if err != nil {
		return nil, err
	}
	return &SolovayStrassenTest{base}, nil
}

func solovayStrassenRound(n, a *big.Int) (bool, error) {
	nt := NumberTheory{}
	jacobi, err := nt.JacobiSymbol(a, n)
	if err != nil {
		return false, err
	}
	if jacobi == 0 {
		return false, nil
	}
	exponent := new(big.Int).Rsh(new(big.Int).Sub(n, big.NewInt(1)), 1)
	residue, err := nt.ModExp(a, exponent, n)
	if err != nil {
		return false, err
	}
	expected := big.NewInt(int64(jacobi))
	expected.Mod(expected, n)
	return residue.Cmp(expected) == 0, nil
}

type MillerRabinTest struct{ *ProbabilisticTestBase }

func NewMillerRabinTest() (*MillerRabinTest, error) {
	base, err := NewProbabilisticTestBase(millerRabinRound, 0.25)
	if err != nil {
		return nil, err
	}
	return &MillerRabinTest{base}, nil
}

func millerRabinRound(n, a *big.Int) (bool, error) {
	d := new(big.Int).Sub(n, big.NewInt(1))
	s := 0
	for d.Bit(0) == 0 {
		d.Rsh(d, 1)
		s++
	}

	nt := NumberTheory{}
	x, err := nt.ModExp(a, d, n)
	if err != nil {
		return false, err
	}
	if x.Cmp(big.NewInt(1)) == 0 || x.Cmp(new(big.Int).Sub(n, big.NewInt(1))) == 0 {
		return true, nil
	}
	minusOne := new(big.Int).Sub(n, big.NewInt(1))
	for r := 1; r < s; r++ {
		x.Mul(x, x).Mod(x, n)
		if x.Cmp(minusOne) == 0 {
			return true, nil
		}
		if x.Cmp(big.NewInt(1)) == 0 {
			return false, nil
		}
	}
	return false, nil
}

func NewPrimalityTest(kind PrimalityKind) (PrimalityTest, error) {
	switch kind {
	case Fermat:
		return NewFermatTest()
	case SolovayStrassen:
		return NewSolovayStrassenTest()
	case MillerRabin:
		return NewMillerRabinTest()
	default:
		return nil, errors.New("unknown primality test")
	}
}
