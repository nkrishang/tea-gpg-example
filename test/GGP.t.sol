// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";

contract ClaimableOwnership is Test {

    bytes32 public constant MESSAGE = hex"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

    address public owner;
    bytes32 public immutable publicKeyHash;

    constructor(bytes32 _keyHash) {
        publicKeyHash = _keyHash;
    }

    function claim(bytes calldata publicKey, bytes calldata signature) external {

        require(owner == address(0), "Ownership claimed");

        // Build precompile calldata
        bytes memory precompileCalldata = abi.encodePacked(MESSAGE, publicKey.length, publicKey, signature.length, signature);

        // Simulate precompile call
        string[] memory inputs = new string[](4);
        inputs[0] = "go";
        inputs[1] = "run";
        inputs[2] = "precompile/run/main.go";
        inputs[3] = vm.toString(precompileCalldata);
        bytes memory result = vm.ffi(inputs);
        
        bool verified = abi.decode(result, (bool));
        require(verified, "Verification failed");

        owner = msg.sender;
    }
}

contract GPGTest is Test {

    ClaimableOwnership target;
    
    address public alice = address(0x123);

    function setUp() public {
        // Get public key (bytes representation) and store its hash.
        string[] memory inputs = new string[](3);

        inputs[0] = "go";
        inputs[1] = "run";
        inputs[2] = "precompile/publicKey/main.go";

        bytes memory pubKey = vm.ffi(inputs);

        // Create target
        target = new ClaimableOwnership(keccak256(pubKey));
    }


    function test_precompile() public {
        // Get precompile inputs
        string[] memory inputs = new string[](3);

        inputs[0] = "go";
        inputs[1] = "run";
        inputs[2] = "precompile/inputs/main.go";

        bytes memory result = vm.ffi(inputs);
        (bytes memory publicKey, bytes memory signature) = abi.decode(result, (bytes, bytes));
        
        vm.prank(alice);
        target.claim(
            publicKey,
            signature
        );
        
        assertEq(target.owner(), alice);
    }
}