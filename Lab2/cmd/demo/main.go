package main

import (
	"fmt"
	"math/big"
	"fiitcrypt/lab2"
)

func main() {
	nt := lab2.NumberTheory{}
	gcd, err := nt.GCD(big.NewInt(240), big.NewInt(46))
	check(err)
	binaryGCD, err := nt.BinaryGCD(big.NewInt(240), big.NewInt(46))
	check(err)
	bezout, err := nt.ExtendedGCD(big.NewInt(240), big.NewInt(46))
	check(err)
	legendre, err := nt.LegendreSymbol(big.NewInt(2), big.NewInt(7))
	check(err)
	jacobi, err := nt.JacobiSymbol(big.NewInt(5), big.NewInt(21))
	check(err)
	modPower, err := nt.ModExp(big.NewInt(7), big.NewInt(128), big.NewInt(13))
	check(err)
	inverse, err := nt.ModularInverse(big.NewInt(17), big.NewInt(3120))
	check(err)
	phiDefinition, err := nt.EulerPhiByDefinition(big.NewInt(360))
	check(err)
	phi, err := nt.EulerPhiByFactorization(big.NewInt(360))
	check(err)
	phiDFT, err := nt.EulerPhiByDFT(big.NewInt(360))
	check(err)
	lambda, err := nt.CarmichaelLambda(big.NewInt(360))
	check(err)
	fmt.Printf("GCD: Euclidean=%s, binary=%s; Bezout=(%s,%s)\n", gcd, binaryGCD, bezout.X, bezout.Y)
	fmt.Printf("Legendre(2,7)=%d; Jacobi(5,21)=%d; 7^128 mod 13=%s; inverse(17 mod 3120)=%s\n",
		legendre, jacobi, modPower, inverse)
	fmt.Printf("phi(360): definition=%s, factorization=%s, DFT=%s; lambda(360)=%s\n",
		phiDefinition, phi, phiDFT, lambda)

	for name, kind := range map[string]lab2.PrimalityKind{
		"Fermat":           lab2.Fermat,
		"Solovay-Strassen": lab2.SolovayStrassen,
		"Miller-Rabin":     lab2.MillerRabin,
	} {
		test, err := lab2.NewPrimalityTest(kind)
		check(err)
		prime, err := test.Test(big.NewInt(97), 0.99)
		check(err)
		fmt.Printf("%s test: 97 is probably prime = %v\n", name, prime)
	}

	service, err := lab2.NewRSAService(lab2.MillerRabin, 0.99, 256)
	check(err)
	pair, err := service.GenerateKeyPair()
	check(err)
	message := []byte{0, 1, 2, 0, 255, 'G', 'o'}
	ciphertext, err := service.Encrypt(message)
	check(err)
	plaintext, err := service.Decrypt(ciphertext)
	check(err)
	fmt.Printf("RSA round-trip: %v; modulus bits=%d\n", string(plaintext) == string(message), pair.Public.N.BitLen())

	vulnerable, err := service.GenerateWienerVulnerableKeyPair()
	check(err)
	attack, err := (lab2.WienerAttackService{}).Attack(vulnerable.Public)
	check(err)
	fmt.Printf("Wiener attack found d=%v after checking %d convergents\n",
		attack.Found, len(attack.Convergents))
	if attack.Found {
		fmt.Printf("recovered d=%s, phi(n)=%s\n", attack.D, attack.Phi)
	}
}

func check(err error) {
	if err != nil {
		panic(err)
	}
}
