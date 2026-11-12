package lab2

import (
	"math/big"
	"testing"
)

func TestGCDVariantsAndBezout(t *testing.T) {
	nt := NumberTheory{}
	a, b := big.NewInt(-240), big.NewInt(46)
	for name, gcdFunc := range map[string]func(*big.Int, *big.Int) (*big.Int, error){
		"euclidean": nt.GCD,
		"binary":    nt.BinaryGCD,
	} {
		got, err := gcdFunc(a, b)
		if err != nil || got.Cmp(big.NewInt(2)) != 0 {
			t.Fatalf("%s gcd: got %v, err %v", name, got, err)
		}
	}
	result, err := nt.ExtendedGCD(a, b)
	if err != nil {
		t.Fatal(err)
	}
	identity := new(big.Int).Add(
		new(big.Int).Mul(a, result.X),
		new(big.Int).Mul(b, result.Y),
	)
	if result.GCD.Cmp(big.NewInt(2)) != 0 || identity.Cmp(result.GCD) != 0 {
		t.Fatalf("invalid Bezout result: %+v", result)
	}
}

func TestSymbolsAndModExp(t *testing.T) {
	nt := NumberTheory{}
	legendre, err := nt.LegendreSymbol(big.NewInt(2), big.NewInt(7))
	if err != nil || legendre != 1 {
		t.Fatalf("Legendre(2,7) = %d, %v", legendre, err)
	}
	jacobi, err := nt.JacobiSymbol(big.NewInt(5), big.NewInt(21))
	if err != nil || jacobi != 1 {
		t.Fatalf("Jacobi(5,21) = %d, %v", jacobi, err)
	}
	power, err := nt.ModExp(big.NewInt(-2), big.NewInt(5), big.NewInt(13))
	if err != nil || power.Cmp(big.NewInt(7)) != 0 {
		t.Fatalf("(-2)^5 mod 13 = %v, %v", power, err)
	}
	inverse, err := nt.ModularInverse(big.NewInt(17), big.NewInt(3120))
	if err != nil || new(big.Int).Mod(new(big.Int).Mul(big.NewInt(17), inverse), big.NewInt(3120)).Cmp(big.NewInt(1)) != 0 {
		t.Fatalf("modular inverse of 17 mod 3120 = %v, %v", inverse, err)
	}
}

func TestJacobiMatchesLegendreForSmallPrimes(t *testing.T) {
	nt := NumberTheory{}
	for p := int64(3); p < 100; p += 2 {
		if !isSmallPrime(p) {
			continue
		}
		for a := int64(-20); a <= 20; a++ {
			jacobi, err := nt.JacobiSymbol(big.NewInt(a), big.NewInt(p))
			if err != nil {
				t.Fatal(err)
			}
			legendre, err := nt.LegendreSymbol(big.NewInt(a), big.NewInt(p))
			if err != nil {
				t.Fatal(err)
			}
			if jacobi != legendre {
				t.Fatalf("Jacobi(%d,%d)=%d, Legendre=%d", a, p, jacobi, legendre)
			}
		}
	}
}

func TestEulerPhiAndCarmichael(t *testing.T) {
	nt := NumberTheory{}
	n := big.NewInt(360)
	wantPhi := big.NewInt(96)
	for name, calculate := range map[string]func(*big.Int) (*big.Int, error){
		"definition":    nt.EulerPhiByDefinition,
		"factorization": nt.EulerPhiByFactorization,
		"dft":           nt.EulerPhiByDFT,
	} {
		got, err := calculate(n)
		if err != nil || got.Cmp(wantPhi) != 0 {
			t.Fatalf("%s phi(360) = %v, %v", name, got, err)
		}
	}
	lambda, err := nt.CarmichaelLambda(n)
	if err != nil || lambda.Cmp(big.NewInt(12)) != 0 {
		t.Fatalf("lambda(360) = %v, %v", lambda, err)
	}
	for _, test := range []struct {
		n, want int64
	}{{1, 1}, {2, 1}, {4, 2}, {8, 2}, {16, 4}, {32, 8}} {
		got, err := nt.CarmichaelLambda(big.NewInt(test.n))
		if err != nil || got.Cmp(big.NewInt(test.want)) != 0 {
			t.Fatalf("lambda(%d) = %v, %v; want %d", test.n, got, err, test.want)
		}
	}
	for value := int64(1); value <= 100; value++ {
		n := big.NewInt(value)
		byDefinition, err := nt.EulerPhiByDefinition(n)
		if err != nil {
			t.Fatal(err)
		}
		byFactorization, err := nt.EulerPhiByFactorization(n)
		if err != nil {
			t.Fatal(err)
		}
		byDFT, err := nt.EulerPhiByDFT(n)
		if err != nil {
			t.Fatal(err)
		}
		if byDefinition.Cmp(byFactorization) != 0 || byDefinition.Cmp(byDFT) != 0 {
			t.Fatalf("phi(%d): definition=%s factorization=%s DFT=%s",
				value, byDefinition, byFactorization, byDFT)
		}
	}
}

func TestProbabilisticPrimalityTests(t *testing.T) {
	tests := []struct {
		name string
		test PrimalityTest
	}{
		{"Fermat", mustFermat(t)},
		{"Solovay-Strassen", mustSolovay(t)},
		{"Miller-Rabin", mustMillerRabin(t)},
	}
	for _, test := range tests {
		for _, candidate := range []struct {
			n    int64
			want bool
		}{{2, true}, {97, true}, {341, false}, {1001, false}} {
			got, err := test.test.Test(big.NewInt(candidate.n), 0.99)
			if err != nil || got != candidate.want {
				t.Fatalf("%s(%d) = %v, %v; want %v", test.name, candidate.n, got, err, candidate.want)
			}
		}
	}
}

func TestRSAEncryptionAndKeyGeneration(t *testing.T) {
	service := mustRSAService(t, MillerRabin, 0.99, 192)
	pair, err := service.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	bound := new(big.Int).Quo(fourthRoot(pair.Public.N), big.NewInt(3))
	if pair.Private.D.Cmp(bound) <= 0 {
		t.Fatal("regular RSA key does not meet the Wiener exponent lower bound")
	}
	message := []byte{0, 0, 1, 2, 0, 255, 0, 7}
	ciphertext, err := service.Encrypt(message)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := service.Decrypt(ciphertext)
	if err != nil || string(plaintext) != string(message) {
		t.Fatalf("RSA round-trip = %v, %v", plaintext, err)
	}
	emptyCiphertext, err := RSAEncrypt(nil, pair.Public)
	if err != nil {
		t.Fatal(err)
	}
	empty, err := RSADecrypt(emptyCiphertext, pair.Private)
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty RSA round-trip = %v, %v", empty, err)
	}

	attack, err := (WienerAttackService{}).Attack(pair.Public)
	if err != nil {
		t.Fatal(err)
	}
	if attack.Found {
		t.Fatal("generated regular key unexpectedly vulnerable to Wiener's attack")
	}
}

func TestWienerAttackOnGeneratedWeakKey(t *testing.T) {
	service := mustRSAService(t, MillerRabin, 0.99, 128)
	pair, err := service.GenerateWienerVulnerableKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	result, err := (WienerAttackService{}).Attack(pair.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Found || result.D.Cmp(pair.Private.D) != 0 {
		t.Fatalf("Wiener attack result = %+v, expected d=%s", result, pair.Private.D)
	}
	bound := new(big.Int).Quo(fourthRoot(pair.Public.N), big.NewInt(3))
	if pair.Private.D.Cmp(bound) >= 0 {
		t.Fatal("generated key is not below Wiener's vulnerable exponent bound")
	}
}

func mustFermat(t *testing.T) PrimalityTest {
	t.Helper()
	test, err := NewFermatTest()
	if err != nil {
		t.Fatal(err)
	}
	return test
}

func mustSolovay(t *testing.T) PrimalityTest {
	t.Helper()
	test, err := NewSolovayStrassenTest()
	if err != nil {
		t.Fatal(err)
	}
	return test
}

func mustMillerRabin(t *testing.T) PrimalityTest {
	t.Helper()
	test, err := NewMillerRabinTest()
	if err != nil {
		t.Fatal(err)
	}
	return test
}

func mustRSAService(t *testing.T, kind PrimalityKind, confidence float64, bits int) *RSAService {
	t.Helper()
	service, err := NewRSAService(kind, confidence, bits)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func isSmallPrime(n int64) bool {
	if n < 2 {
		return false
	}
	for divisor := int64(2); divisor*divisor <= n; divisor++ {
		if n%divisor == 0 {
			return false
		}
	}
	return true
}
