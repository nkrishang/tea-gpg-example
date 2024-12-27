## tea.xyz: GPG EdDSA precompile

`test/GPG.t.sol` showcases the use of a GPG EdDSA precompile.

`ClaimableOwnership` is a contract with a hardcoded `MESSAGE` and immutable `bytes32 publicKeyHash` variable. It contains a `claim` function:

```solidity
function claim(bytes calldata publicKey, bytes calldata signature) external;
```

This function lets an actor claim ownership of the contract by presenting the pre-image of publicKeyHash (i.e. `keccak256(publicKey) == publicKeyHash`) and a signature produced by signing the hardcoded `MESSAGE`.

The public key is expected to be an (unarmored) ed25519 public key managed via GPG. Similarly, the signature is expected to be an (unarmored) signature produced by signing the 32 bytes hex `MESSAGE` via gpg, using the corresponding private key.

This armored public key can be exported by running:

```bash
gpg --list-keys
```

```bash
gpg --export --armor <key-id>
```

The armored signature is produced by signing the message via gpg:

```bash
echo <message> | xxd -r -p | gpg --pinentry-mode loopback --detach-sign --armor
```

Both commands produce armored values which you should paste in `/precompile`. Then, run the test:

```bash
forge test
```

## Usage

### Install

```shell
forge install
```

```shell
go mod tidy
```

### Build

```shell
forge build
```

### Test

```shell
forge test
```

### Format

```shell
forge fmt
```

## Feedback

Please open an issue to provide any feedback. Thanks!
