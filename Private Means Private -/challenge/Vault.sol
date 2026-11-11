// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;
    uint256 public attempts;
    bytes32 private rescueCodePart1;
    bytes32 private rescueCodePart2;

    constructor(bytes32 part1, bytes32 part2) {
        owner = msg.sender;
        attempts = 0;
        rescueCodePart1 = part1;
        rescueCodePart2 = part2;
    }

    function ping() external {
        attempts += 1;
    }
}
