package lab2

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
)

type RSAPublicKey struct {
	N *big.Int
	E *big.Int
}

type RSAPrivateKey struct {
	N *big.Int
	D *big.Int
}

type RSAKeyPair struct {
	Public  RSAPublicKey
	Private RSAPrivateKey
}

// RSAService owns a nested key-generation service and the currently active pair.
type RSAService struct {
	KeyGenerator *RSAKeyGenerator
	active       *RSAKeyPair
}

// RSAKeyGenerator is the Go equivalent of the nested key-generation service.
// Go has no nested type declarations, so RSAService owns this service.
type RSAKeyGenerator struct {
	test       PrimalityTest
	confidence float64
	bitLength  int
}

func NewRSAService(kind PrimalityKind, minimumConfidence float64, bitLength int) (*RSAService, error) {
	test, err := NewPrimalityTest(kind)
	if err != nil {
		return nil, err
	}
	if minimumConfidence < 0.5 || minimumConfidence >= 1 || math.IsNaN(minimumConfidence) {
		return nil, errors.New("minimum confidence must be in [0.5, 1)")
	}
	if bitLength < 32 {
		return nil, errors.New("RSA modulus length must be at least 32 bits")
	}
	generator := &RSAKeyGenerator{
		test:       test,
		confidence: minimumConfidence,
		bitLength:  bitLength,
	}
	return &RSAService{KeyGenerator: generator}, nil
}

func (generator *RSAKeyGenerator) GenerateKeyPair() (RSAKeyPair, error) {
	return generator.generateKeyPair(false)
}

func (generator *RSAKeyGenerator) GenerateWienerVulnerableKeyPair() (RSAKeyPair, error) {
	return generator.generateKeyPair(true)
}

func (generator *RSAKeyGenerator) generateKeyPair(vulnerableToWiener bool) (RSAKeyPair, error) {
	if generator == nil || generator.test == nil {
		return RSAKeyPair{}, errors.New("RSA key generator is not configured")
	}
	pBits := generator.bitLength / 2
	qBits := generator.bitLength - pBits
	minPrimeBits := pBits
	if qBits < minPrimeBits {
		minPrimeBits = qBits
	}
	minimumGap := new(big.Int).Lsh(big.NewInt(1), uint(minPrimeBits-3))
	nt := NumberTheory{}

	for {
		p, err := generator.generatePrime(pBits)
		if err != nil {
			return RSAKeyPair{}, err
		}
		var q *big.Int
		for {
			q, err = generator.generatePrime(qBits)
			if err != nil {
				return RSAKeyPair{}, err
			}
			if p.Cmp(q) != 0 && absDifference(p, q).Cmp(minimumGap) >= 0 {
				break
			}
		}
		n := new(big.Int).Mul(p, q)
		if n.BitLen() != generator.bitLength {
			continue
		}
		phi := new(big.Int).Mul(
			new(big.Int).Sub(p, big.NewInt(1)),
			new(big.Int).Sub(q, big.NewInt(1)),
		)

		if vulnerableToWiener {
			pair, err := makeWienerVulnerablePair(n, phi)
			if err != nil {
				continue
			}
			return pair, nil
		}

		d, err := chooseWienerSafeExponent(n, phi)
		if err != nil {
			continue
		}
		e, err := nt.ModularInverse(d, phi)
		if err != nil || e.Cmp(big.NewInt(1)) <= 0 {
			continue
		}
		check, err := nt.GCD(e, phi)
		if err != nil {
			return RSAKeyPair{}, err
		}
		if check.Cmp(big.NewInt(1)) != 0 {
			continue
		}
		return RSAKeyPair{
			Public:  RSAPublicKey{N: new(big.Int).Set(n), E: e},
			Private: RSAPrivateKey{N: new(big.Int).Set(n), D: d},
		}, nil
	}
}

func (generator *RSAKeyGenerator) generatePrime(bits int) (*big.Int, error) {
	for {
		candidate, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(bits)))
		if err != nil {
			return nil, err
		}
		candidate.SetBit(candidate, bits-1, 1)
		candidate.SetBit(candidate, 0, 1)
		prime, err := generator.test.Test(candidate, generator.confidence)
		if err != nil {
			return nil, err
		}
		if prime {
			return candidate, nil
		}
	}
}

func chooseWienerSafeExponent(n, phi *big.Int) (*big.Int, error) {
	threshold := new(big.Int).Quo(fourthRoot(n), big.NewInt(3))
	threshold.Add(threshold, big.NewInt(1))
	span := new(big.Int).Sub(phi, threshold)
	if span.Sign() <= 0 {
		return nil, errors.New("modulus too small to select a Wiener-safe private exponent")
	}
	for {
		delta, err := rand.Int(rand.Reader, span)
		if err != nil {
			return nil, err
		}
		d := new(big.Int).Add(delta, threshold)
		if d.Bit(0) == 0 {
			d.Add(d, big.NewInt(1))
		}
		if d.Cmp(phi) >= 0 {
			continue
		}
		gcd, err := (NumberTheory{}).GCD(d, phi)
		if err != nil {
			return nil, err
		}
		if gcd.Cmp(big.NewInt(1)) == 0 {
			return d, nil
		}
	}
}

func makeWienerVulnerablePair(n, phi *big.Int) (RSAKeyPair, error) {
	limit := new(big.Int).Quo(fourthRoot(n), big.NewInt(3))
	if limit.Cmp(big.NewInt(5)) < 0 {
		return RSAKeyPair{}, errors.New("modulus too small for a useful Wiener-vulnerable key")
	}
	maxD := new(big.Int).Set(limit)
	if maxD.Cmp(big.NewInt(1<<20)) > 0 {
		maxD.SetInt64(1 << 20)
	}
	for d := big.NewInt(5); d.Cmp(maxD) < 0; d.Add(d, big.NewInt(2)) {
		gcd, err := (NumberTheory{}).GCD(d, phi)
		if err != nil {
			return RSAKeyPair{}, err
		}
		if gcd.Cmp(big.NewInt(1)) != 0 {
			continue
		}
		e, err := (NumberTheory{}).ModularInverse(d, phi)
		if err != nil || e.Cmp(big.NewInt(1)) <= 0 || e.Cmp(n) >= 0 {
			continue
		}
		return RSAKeyPair{
			Public:  RSAPublicKey{N: new(big.Int).Set(n), E: e},
			Private: RSAPrivateKey{N: new(big.Int).Set(n), D: new(big.Int).Set(d)},
		}, nil
	}
	return RSAKeyPair{}, errors.New("could not find a small private exponent coprime to phi(n)")
}

func (service *RSAService) GenerateKeyPair() (RSAKeyPair, error) {
	if service == nil || service.KeyGenerator == nil {
		return RSAKeyPair{}, errors.New("RSA key generator is not configured")
	}
	pair, err := service.KeyGenerator.GenerateKeyPair()
	if err != nil {
		return RSAKeyPair{}, err
	}
	active := cloneKeyPair(pair)
	service.active = &active
	return cloneKeyPair(pair), nil
}

func (service *RSAService) GenerateWienerVulnerableKeyPair() (RSAKeyPair, error) {
	if service == nil || service.KeyGenerator == nil {
		return RSAKeyPair{}, errors.New("RSA key generator is not configured")
	}
	pair, err := service.KeyGenerator.GenerateWienerVulnerableKeyPair()
	if err != nil {
		return RSAKeyPair{}, err
	}
	active := cloneKeyPair(pair)
	service.active = &active
	return cloneKeyPair(pair), nil
}

func (service *RSAService) Encrypt(data []byte) ([]byte, error) {
	if service == nil {
		return nil, errors.New("RSA service is nil")
	}
	if service.active == nil {
		return nil, errors.New("generate an RSA key pair before encryption")
	}
	return RSAEncrypt(data, service.active.Public)
}

func (service *RSAService) Decrypt(ciphertext []byte) ([]byte, error) {
	if service == nil {
		return nil, errors.New("RSA service is nil")
	}
	if service.active == nil {
		return nil, errors.New("generate an RSA key pair before decryption")
	}
	return RSADecrypt(ciphertext, service.active.Private)
}

// RSAEncrypt uses length-framed, fixed-width ciphertext blocks. It does not add
// probabilistic encryption padding and therefore is for coursework only.
func RSAEncrypt(data []byte, key RSAPublicKey) ([]byte, error) {
	if key.N == nil || key.E == nil || key.N.Cmp(big.NewInt(3)) < 0 ||
		key.N.Bit(0) == 0 || key.E.Cmp(big.NewInt(1)) <= 0 || key.E.Cmp(key.N) >= 0 {
		return nil, errors.New("invalid RSA public key")
	}
	payloadSize := (key.N.BitLen()-1)/8 - 1
	if payloadSize <= 0 {
		return nil, errors.New("RSA modulus is too small for framed encryption")
	}
	cipherBlockSize := (key.N.BitLen() + 7) / 8
	blockCount := (len(data) + payloadSize - 1) / payloadSize
	result := make([]byte, 8+blockCount*cipherBlockSize)
	binary.BigEndian.PutUint64(result[:8], uint64(len(data)))

	nt := NumberTheory{}
	for offset, blockIndex := 0, 0; offset < len(data); offset, blockIndex = offset+payloadSize, blockIndex+1 {
		end := offset + payloadSize
		if end > len(data) {
			end = len(data)
		}
		message := new(big.Int).SetBytes(data[offset:end])
		if message.Cmp(key.N) >= 0 {
			return nil, fmt.Errorf("plaintext block %d is not smaller than the modulus", blockIndex)
		}
		encrypted, err := nt.ModExp(message, key.E, key.N)
		if err != nil {
			return nil, err
		}
		encrypted.FillBytes(result[8+blockIndex*cipherBlockSize : 8+(blockIndex+1)*cipherBlockSize])
	}
	return result, nil
}

func RSADecrypt(ciphertext []byte, key RSAPrivateKey) ([]byte, error) {
	if key.N == nil || key.D == nil || key.N.Cmp(big.NewInt(3)) < 0 ||
		key.N.Bit(0) == 0 || key.D.Cmp(big.NewInt(1)) <= 0 {
		return nil, errors.New("invalid RSA private key")
	}
	if len(ciphertext) < 8 {
		return nil, errors.New("RSA ciphertext is missing its length header")
	}
	plainLength := binary.BigEndian.Uint64(ciphertext[:8])
	if plainLength > uint64(^uint(0)>>1) {
		return nil, errors.New("declared plaintext length exceeds addressable memory")
	}
	payloadSize := (key.N.BitLen()-1)/8 - 1
	cipherBlockSize := (key.N.BitLen() + 7) / 8
	if payloadSize <= 0 || (len(ciphertext)-8)%cipherBlockSize != 0 {
		return nil, errors.New("RSA ciphertext has an invalid block length")
	}
	blockCount := (len(ciphertext) - 8) / cipherBlockSize
	expectedCount := 0
	if plainLength != 0 {
		expectedCount = int((plainLength + uint64(payloadSize) - 1) / uint64(payloadSize))
	}
	if blockCount != expectedCount {
		return nil, errors.New("RSA ciphertext block count does not match the length header")
	}

	result := make([]byte, int(plainLength))
	nt := NumberTheory{}
	for index := 0; index < blockCount; index++ {
		start := 8 + index*cipherBlockSize
		encrypted := new(big.Int).SetBytes(ciphertext[start : start+cipherBlockSize])
		if encrypted.Cmp(key.N) >= 0 {
			return nil, fmt.Errorf("ciphertext block %d is outside the RSA modulus", index)
		}
		message, err := nt.ModExp(encrypted, key.D, key.N)
		if err != nil {
			return nil, err
		}

		outStart := index * payloadSize
		outEnd := outStart + payloadSize
		if outEnd > len(result) {
			outEnd = len(result)
		}
		block := message.Bytes()
		if len(block) > outEnd-outStart {
			return nil, fmt.Errorf("decrypted block %d exceeds its expected length", index)
		}
		copy(result[outEnd-len(block):outEnd], block)
	}
	return result, nil
}

func cloneKeyPair(pair RSAKeyPair) RSAKeyPair {
	return RSAKeyPair{
		Public: RSAPublicKey{
			N: new(big.Int).Set(pair.Public.N),
			E: new(big.Int).Set(pair.Public.E),
		},
		Private: RSAPrivateKey{
			N: new(big.Int).Set(pair.Private.N),
			D: new(big.Int).Set(pair.Private.D),
		},
	}
}

func absDifference(a, b *big.Int) *big.Int {
	return new(big.Int).Abs(new(big.Int).Sub(a, b))
}

func fourthRoot(n *big.Int) *big.Int {
	return new(big.Int).Sqrt(new(big.Int).Sqrt(new(big.Int).Set(n)))
}
