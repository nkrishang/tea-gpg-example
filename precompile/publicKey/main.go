package main

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/openpgp/armor"
)

func main() {
	// PASTE armored public key here. [1] gpg --list-keys [2] gpg --export --armor <key-id>
	armoredPublicKey := `-----BEGIN PGP PUBLIC KEY BLOCK-----

mDMEZ2pdDhYJKwYBBAHaRw8BAQdAXRCrGQMPij7crOE9DhZjZ9KV8eEU74fI8wCc
2pMaDuu0K0tyaXNoYW5nIE5hZGdhdWRhIDxrcmlzaGFuZy5ub3RlQGdtYWlsLmNv
bT6IkwQTFgoAOxYhBMDC3NihB0bkfHWxgZZ2cvhFREO4BQJnal0OAhsDBQsJCAcC
AiICBhUKCQgLAgQWAgMBAh4HAheAAAoJEJZ2cvhFREO4IkIA/3XEValP5MgubFFv
UjrsGdQoV/F6dOHHQCQBVA+e1wwdAP4qLk4/WhNghLy1ql9o6Jladb+NCpPMAkUJ
5BVkQ7NQBLg4BGdqXQ4SCisGAQQBl1UBBQEBB0AVE0Dqu6r5Cn3ahWK4IXQtBo0a
QWgdfhUu779zBCyjLgMBCAeIeAQYFgoAIBYhBMDC3NihB0bkfHWxgZZ2cvhFREO4
BQJnal0OAhsMAAoJEJZ2cvhFREO42UgBAP2hw1hELhVWEv4K91fy7rlP6mXZ+Q3a
pXurN2g4kMGfAPwJz24Hsjj4E2HtucwRn8h2uV9oqgAdgwjVPY8/mdz8Ag==
=3g4k
-----END PGP PUBLIC KEY BLOCK-----`

	publicKey, err := armoredToBytes(armoredPublicKey)
	if err != nil {
		panic(err)
	}

	// Print publicKey as a hex string
	fmt.Println(hex.EncodeToString(publicKey))
}

func armoredToBytes(armoredData string) ([]byte, error) {
	block, err := armor.Decode(bytes.NewReader([]byte(armoredData)))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(block.Body)
}
