package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ethereum/go-ethereum/common"
)

func main() {

	// Get `calldata` bytes value as an argument
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: go run main.go <calldata>")
		os.Exit(1)
	}

	// Decode the calldata from a hex string
	calldata, err := hex.DecodeString(os.Args[1][2:]) // Don't use the "0x" of "0x..."
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode calldata: %v\n", err)
		os.Exit(1)
	}

	// Test against `Run`
	contract := &gpgEd25519Verify{}
	result, err := contract.Run(calldata)
	if err != nil {
		fmt.Printf("Verification failed: %v\n", err)
		return
	}

	fmt.Println(hex.EncodeToString(result));
}

// gpgEd25519Verify implements native verification for ed25519 signatures produced via gpg
type gpgEd25519Verify struct{}

var (
	errInputTooShort    = errors.New("input too short")
	errInvalidPublicKey   = errors.New("invalid public key")
)


// Run performs ed25519 signature verification
func (c *gpgEd25519Verify) Run(input []byte) ([]byte, error) {
	// Input should be: message (32 bytes) || pubkey_len (32 bytes) || pubkey || sig_len (32 bytes) || signature

	// Extract message
	msgLen := 32
	if len(input) < msgLen {
		return nil, errInputTooShort
	}

	message := input[:msgLen]
	messageObj := pgpcrypto.NewPlainMessage(message)

	// Extract public key length and public key
	offset := msgLen
	if len(input) < offset + 32 {
		return nil, errInputTooShort
	}
	
	pubKeyLen := int(new(big.Int).SetBytes(input[offset : offset+32]).Uint64())
	if len(input) < int(offset+32+pubKeyLen) {
		return nil, errInputTooShort
	}
	pubKey := input[offset+32 : offset+32+pubKeyLen]

	// Create public key object
	pubKeyObj, err := pgpcrypto.NewKey(pubKey)
	if err != nil {
		return nil, errInvalidPublicKey
	}

	// Create public keyring
	pubKeyRing, err := pgpcrypto.NewKeyRing(pubKeyObj)
	if err != nil {
		return nil, errInvalidPublicKey
	}

	// Extract signature length and signature
	offset = offset + 32 + pubKeyLen
	if len(input) < offset + 32 {
		return nil, errInputTooShort
	}

	sigLen := int(new(big.Int).SetBytes(input[offset : offset+32]).Uint64())
	if len(input) < int(offset+32+sigLen) {
		return nil, errInputTooShort
	}
	signature := input[offset+32 : offset+32+sigLen]

	// Create signature object
	signatureObj := pgpcrypto.NewPGPSignature(signature)

	// Verify signature
	err = pubKeyRing.VerifyDetached(messageObj, signatureObj, 0)
	if err != nil {
		// Return 32 bytes: 0 for failure
		return common.LeftPadBytes([]byte{0}, 32), nil
	}

	// Return 32 bytes: 1 for success, 0 for failure
	return common.LeftPadBytes([]byte{1}, 32), nil
}
