package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ethereum/go-ethereum/accounts/abi"
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
	errDecodingFailed    = errors.New("failed to decode input")
	errInvalidPublicKey   = errors.New("invalid public key")
)

// Run performs ed25519 signature verification
func (c *gpgEd25519Verify) Run(input []byte) ([]byte, error) {
	// Input should be: abi.encode(bytes32 message, bytes publicKey, bytes signature)
	
	decode := func(encodedInput []byte) ([32]byte, []byte, []byte, error) {
		// Define ABI types
		bytesType, err := abi.NewType("bytes", "", nil)
		if err != nil {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to create bytes type: %v", err)
		}
		bytes32Type, err := abi.NewType("bytes32", "", nil)
		if err != nil {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to create bytes32 type: %v", err)
		}

		// Create ABI arguments
		arguments := abi.Arguments{
			{Type: bytes32Type},
			{Type: bytesType},
			{Type: bytesType},
		}

		// Unpack the encoded data
		unpacked, err := arguments.Unpack(encodedInput)
		if err != nil {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to unpack data: %v", err)
		}

		// Ensure we have the correct number of elements
		if len(unpacked) != 3 {
			return [32]byte{}, nil, nil, fmt.Errorf("unexpected number of decoded arguments: got %d, want 3", len(unpacked))
		}

		// Extract each value
		message, ok := unpacked[0].([32]byte)
		if !ok {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to cast message to [32]byte")
		}
		publicKey, ok := unpacked[1].([]byte)
		if !ok {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to cast publicKey to []byte")
		}
		signature, ok := unpacked[2].([]byte)
		if !ok {
			return [32]byte{}, nil, nil, fmt.Errorf("failed to cast signature to []byte")
		}

		return message, publicKey, signature, nil
	}

	message, pubKey, signature, err := decode(input)
	if err != nil {
		return nil, errDecodingFailed
	}

	// Create message object
	messageObj := pgpcrypto.NewPlainMessage(message[:])

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
