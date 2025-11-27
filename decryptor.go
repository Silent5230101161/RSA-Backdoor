package main

import (
	"crypto/rsa"
	"crypto/sha3"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
)

// --- Math utils --- //

// Check if a number is prime
func isPrime(n *big.Int) bool {
	return n.ProbablyPrime(20)
}

// Trapdoor function (SHA3-256)
func H(s string) *big.Int {
	hash := sha3.New256()
	hash.Write([]byte(s))
	return new(big.Int).SetBytes(hash.Sum(nil))
}

// Raw (unpadded) RSA decryption as x=y**d %n
func rawRSADecrypt(c *big.Int, priv *rsa.PrivateKey) *big.Int {
	s := new(big.Int).Exp(c, priv.D, priv.N)
	return s
}

// --- DECRYPTOR --- //

// This function deduces the private key of victim
// We run Yung's 1996 algorithm

func DECRYPTOR(n *big.Int, e *big.Int, privKey *rsa.PrivateKey, bitsize int) (*big.Int, *big.Int, *big.Int) {
	fmt.Println("[*] Extracting private key from SETUP backdoor...")

	// 1. Take the uppermost n/bits of n as u
	c := new(big.Int).Rsh(n, uint(bitsize))

	// 2. Set c1 = u and c2 = u + 1
	c1 := c
	c2 := new(big.Int).Add(c, big.NewInt(1))

	// 3. Decrypt c1 and c2 with the private key (D) generated at the begining to calculate
	// s1 and s2: s1 = c1D mod N and s2 = c2D mod N
	s1 := rawRSADecrypt(c1, privKey)
	s2 := rawRSADecrypt(c2, privKey)

	// 4. Compute p1 = H(s1), p2 = H(s2)
	p1 := H(s1.String())
	p2 := H(s2.String())

	// 5. Check which p divides n
	// The quotient that divides n without a remainder yields q and the appropriate pi yields p
	var p, q *big.Int
	q1, r1 := new(big.Int).DivMod(n, p1, new(big.Int))
	q2, r2 := new(big.Int).DivMod(n, p2, new(big.Int))

	if r1.Sign() == 0 && isPrime(p1) && isPrime(q1) {
		p = p1
		q = q1
		fmt.Printf("[+] Found valid factorization using s1\n")
	} else if r2.Sign() == 0 && isPrime(p2) && isPrime(q2) {
		p = p2
		q = q2
		fmt.Printf("[+] Found valid factorization using s2\n")
	} else {
		log.Fatal("[!] Failed to find prime factorization - key may not be SETUP backdoored or wrong bitsize")
	}

	fmt.Printf("[+] Recovered p (bit length: %d)\n", p.BitLen())
	fmt.Printf("[+] Recovered q (bit length: %d)\n", q.BitLen())

	// 6. Compute d as e*d ≡ 1 mod phi(n)
	pMinus := new(big.Int).Sub(p, big.NewInt(1))
	qMinus := new(big.Int).Sub(q, big.NewInt(1))
	phi := new(big.Int).Mul(pMinus, qMinus)

	d := new(big.Int).ModInverse(e, phi)
	if d == nil {
		log.Fatal("[!] Failed to compute d")
	}

	fmt.Printf("[+] Recovered d (bit length: %d)\n", d.BitLen())

	return d, p, q
}

// --- RSA key manipulation utils --- //

// Load RSA public key from .pem file
func loadPublicKey(filename string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("[!] Failed to parse PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("[!] Not an RSA public key")
	}

	return rsaPub, nil
}

// Load private key from .pem file
func loadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("[!] Failed to parse PEM block")
	}

	// OpenSSL allows multiple padding formats
	// Try PKCS#1
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return priv, nil
	}
	// Try PKCS#8
	privKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("[!] Failed to parse private key: %v", err)
	}

	rsaPriv, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("[!] Not an RSA private key")
	}

	return rsaPriv, nil
}

// Load ciphertext from .bin file
func loadCiphertext(filename string) (*big.Int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	c := new(big.Int).SetBytes(data)
	return c, nil
}

// Load metadata
func loadMetadata(filename string) (int, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return 512, nil // Default bitsize fallback
	}

	var bitsize int
	_, err = fmt.Sscanf(string(data), "bitsize=%d", &bitsize)
	if err != nil {
		return 512, nil // Default fallback
	}
	return bitsize, nil
}

func main() {

	victimPubKey := flag.String("pk", "", "Path to backdoored public key (.pem)")
	attackerPrivKey := flag.String("sk", "", "Path to attacker's private key (.pem)")
	cipherFile := flag.String("c", "", "Path to ciphertext file (.bin)")
	verbose := flag.Bool("v", false, "Verbose output")
	bitsize := flag.Int("bits", 0, "Bit size used for Z (default: 512)")

	flag.Parse()
	if *victimPubKey == "" || *attackerPrivKey == "" || *cipherFile == "" {
		fmt.Println("\n [*] Usage: decryptor -pk <victim_pub.pem> -sk <attacker_priv.pem> -c <cipher.bin>")
		flag.PrintDefaults()
		os.Exit(1)
	}

	// Load pk
	fmt.Println("[*] Loading victim's public key...")
	victimPub, err := loadPublicKey(*victimPubKey)
	if err != nil {
		log.Fatalf("[!] Failed to load victim's public key: %v", err)
	}

	// Load SK
	fmt.Println("[*] Loading attacker's private key...")
	attackerPriv, err := loadPrivateKey(*attackerPrivKey)
	if err != nil {
		log.Fatalf("[!] Failed to load attacker's private key: %v", err)
	}

	// Load ciphertext
	fmt.Println("[*] Loading ciphertext...")
	ciphertext, err := loadCiphertext(*cipherFile)
	if err != nil {
		log.Fatalf("[!] Failed to load ciphertext: %v", err)
	}

	// Check bitsize for z
	detectedBitsize := *bitsize
	if detectedBitsize == 0 {
		metadataPath := filepath.Join(filepath.Dir(*victimPubKey), "metadata.txt")
		detectedBitsize, _ = loadMetadata(metadataPath)
		fmt.Printf("[i] Auto-detected bitsize: %d\n", detectedBitsize)
	}

	if *verbose {
		fmt.Printf("\n[i] Victim's public key (N bit length: %d)\n", victimPub.N.BitLen())
		fmt.Printf("[i] Attacker's key (N bit length: %d)\n", attackerPriv.N.BitLen())
		fmt.Printf("[i] Ciphertext byte length: %d\n\n", len(ciphertext.Bytes()))
	}

	// Run SETUP algorithm to retrieve secret
	e := big.NewInt(int64(victimPub.E))
	d, p, q := DECRYPTOR(victimPub.N, e, attackerPriv, detectedBitsize)

	// Build private key from secret
	victimPriv := &rsa.PrivateKey{
		PublicKey: *victimPub,
		D:         d,
		Primes:    []*big.Int{p, q},
	}
	victimPriv.Precompute()

	fmt.Println("\n[+] Successfully extracted victim's private key!")

	// Decrypt the ciphertext
	fmt.Println("\n[*] Decrypting ciphertext...")
	plaintext := rawRSADecrypt(ciphertext, victimPriv)
	plaintextBytes := plaintext.Bytes()

	fmt.Println("\n--- DECRYPTED MESSAGE ---")
	fmt.Printf("%s\n", plaintextBytes)
	fmt.Println("-------------------------")

	if *verbose {
		fmt.Printf("\n[i] Decryption details:\n")
		fmt.Printf("[i] Plaintext byte length: %d\n", len(plaintextBytes))
		fmt.Printf("[i] Plaintext hex: %x\n", plaintextBytes)
	}
}
