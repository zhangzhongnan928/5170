---
eip: 7xxx
title: Permissionless SmartToken Registry
description: Permissionless registry for smart token scripts
author: Victor Zhang (@zhangzhongnan928) James Brown (@JamesSmartCell)
discussions-to: https://ethereum-magicians.org/t/eip-xxxx-permissionless-registry
status: Draft
type: Standards Track
category: ERC
created: 2024-07-01
requires: 
---

## Abstract

This EIP provides a means to create a standard registry for locating executable scripts associated with the token.

## Motivation

[ERC-5169](https://github.com/ethereum/ERCs/blob/master/ERCS/erc-5169.md) (`scriptURI`) provides a client script lookup method for contracts. ERC-5169 requires the contract to have implemented that interface at the time of construction (or allow an upgrade path).

This proposal outlines a method similar to the ENS system, which provides a contract that allows various methods of supplying debug and certified scripts.

### Overview

The registry contract will supply a URI for a given contract address. This URI points to a script program that can be fetched by a wallet, viewer or mini-dapp.

This pointer can be set using a setter in the registry contract.

The script setter could be authenticated in various ways:

1. If the contract which is specified when the setter is called implements the Ownable interface, and the caller of the setter function matches Ownable then the URI iteself is considered authenticated. There is still further script authentication required, which can take two forms:
  a. The URI points to an IPFS storage location. This script will be considered authenticated.
  b. The script, once downloaded is checked to be signed by the owner() key specified by the Ownable interface, in accordance with the script design. In the case of TokenScript this can be checked by a dapp or wallet using the TokenScript SDK, or by reading the XML and extracting the signature.
2. If the contract does not implement Ownable, or if the account setting the URI does not match the Ownable further checking is required:
  a. The contract pointed to implements Ownable, and the downloaded script is signed by the owner() key.
  b. The contract pointed to does not implement Ownable :- in this case the wallet/dapp or viewer must acertain the deployment key using 3rd party API or block explorer. The implementing wallet, dapp or viewer must then check the signature matches this deployment key.
3. A governance token could allow a script council to authenticate requests to set and validate script locations. If the script is not hosted on IPFS then the verifications rules in (2) above should still apply.

If these criteria are not met, then for mainnet implementations the implementing wallet should at the very least not allow any transactions to be called, and should consider not to even display the script.
For testnets, it is acceptable to allow the script to function, at the discretion of the wallet provider.

## Specification

The keywords “MUST”, “MUST NOT”, “REQUIRED”, “SHALL”, “SHALL NOT”, “SHOULD”, “SHOULD NOT”, “RECOMMENDED”, “MAY” and “OPTIONAL” in this document are to be interpreted as described in RFC 2119.

The contract MUST implement at minimum a getter and setter function for scriptURI.
The contract MUST implement a method to authenticate the wallet which is setting the scriptURI. This could be simplistic as in the given example implementation.
The contract SHOULD provide a method so implementing viewer/wallets can validate script signatures.
The contract SHOULD 



```solidity
interface IDecentralisedRegistry {
    /// @dev This event emits when the scriptURI is updated, 
    /// so wallets implementing this interface can update a cached script
    event ScriptUpdate(address indexed contractAddress, string[] newScriptURI);

    /// @notice Get the scriptURI for the contract
    /// @return The scriptURI
    function scriptURI(address contractAddress) external view returns (string[] memory);

    /// @notice Update the scriptURI 
    /// emits event ScriptUpdate(address indexed contractAddress, scriptURI memory newScriptURI);
    function setScriptURI(address contractAddress, string[] memory scriptURIList) external;
}
```

For example see the Test Case below

## Rationale

This method allows contracts written without the ERC-5169 interface to associate scripts with themselves, and avoids the need for a centralised online server, with subsequent need for security and the requires an organisation to become a gatekeeper for the database.

### Test Contract

```solidity
import "@openzeppelin/contracts/access/Ownable.sol";

contract DecentralisedRegistry as IDecentralisedRegistry {

    struct ScriptEntry {
        string[] scriptURIs;
        address[] delegateSigners; // list of authenticated addresses approved by owner
        address owner; // provides a latch so that 3rd parties can create TokenScript entries
    }

    mapping(address => ScriptEntry) private _scriptURIs;

    event ScriptUpdate(address indexed contractAddress, string[]);
    event RegisterOwner(address indexed contractAddress, address indexed newOwner);
    event AddDelegateSigner(address indexed contractAddress, address indexed newDelegate);
    event RevokeDelegateSigner(address indexed contractAddress, address indexed revokedDelegate);

    function scriptURI(
        address contractAddress
    ) public view returns (string[] memory) {
        return _scriptURIs[contractAddress].scriptURIs;
    }

    function setScriptURI(
        address contractAddress,
        string[] memory scriptURIList
    ) public {
        // in order to set scriptURI array, the sender must adhere to the following rules:
        require(
            isDelegateOrOwner(contractAddress, msg.sender),
            "Not authorized"
        );

        emit ScriptUpdate(contractAddress, scriptURIList);
        _scriptURIs[contractAddress].scriptURIs = scriptURIList;
    }

    function registerOwner(address contractAddress) public {
        ScriptEntry storage existingEntry = _scriptURIs[contractAddress];
        address contractOwner = Ownable(contractAddress).owner();
        address sender = msg.sender;
        require(existingEntry.owner != sender, "Already set to this owner");
        require(
            existingEntry.owner == address(0) || sender == contractOwner,
            "Not authorized"
        );
        emit RegisterOwner(contractAddress, sender);
        existingEntry.owner = sender;
    }

    function isDelegateOrOwner(
        address contractAddress,
        address check
    ) public view returns (bool) {
        ScriptEntry memory existingEntry = _scriptURIs[contractAddress];
        if (check == Ownable(contractAddress).owner()) {
          return true;
        }
        uint256 length = existingEntry.delegateSigners.length;
        for (uint256 i = 0; i < length; ) {
            if (existingEntry.delegateSigners[i] == check) {
                return true;
            }
            unchecked {
                i++;
            }
        }
        return false;
    }

    function getDelegateIndex(
        address contractAddress,
        address check
    ) public view returns (int256) {
        ScriptEntry memory existingEntry = _scriptURIs[contractAddress];
        uint256 length = existingEntry.delegateSigners.length;
        for (uint256 i = 0; i < length; ) {
            if (existingEntry.delegateSigners[i] == check) {
                return int256(i);
            }
            unchecked {
                i++;
            }
        }
        return -1;
    }

    function addDelegateSigner(address contractAddress, address newSigner) public {
        require(
            msg.sender == Ownable(contractAddress).owner(),
            "Owner or Delegate only"
        );
        require(
            getDelegateIndex(contractAddress, newSigner) < 0,
            "Already a delegate signer"
        );
        emit AddDelegateSigner(contractAddress, newSigner);
        _scriptURIs[contractAddress].delegateSigners.push(newSigner);
    }

    function revokeDelegateSigner(
        address contractAddress,
        address signer
    ) public {
        int256 delegateIndex = getDelegateIndex(contractAddress, signer);
        require(
            msg.sender == Ownable(contractAddress).owner(),
            "Contract Owner only"
        );
        require(delegateIndex > -1, "Unable to revoke unknown signer");
        emit RevokeDelegateSigner(contractAddress, signer);
        delete _scriptURIs[contractAddress].delegateSigners[uint256(delegateIndex)];
    }
}
```

### Test Case

```ts

const { expect } = require('chai');
const { BigNumber, Wallet } = require('ethers');
const { ethers, network, getChainId } = require('hardhat');

describe('ERC5169', function () {
  before(async function () {
    this.ERC5169 = await ethers.getContractFactory('ERC5169');
  });

  beforeEach(async function () {
    // targetNFT
    this.erc5169 = await this.ERC5169.deploy();
  });

  it('Should set script URI', async function () {
    const scriptURI = [
      'uri1', 'uri2', 'uri3'
    ];

    await expect(this.erc5169.setScriptURI(scriptURI))
      .emit(this.erc5169, 'ScriptUpdate')
      .withArgs(scriptURI);
    
    const currentScriptURI = await this.erc5169.scriptURI();

    expect(currentScriptURI.toString()).to.be.equal(scriptURI.toString());
  });
  
```

## Reference Implementation

A potential implementation could happen for a staking token. Consider a staking token which uses an NFT token to represent various assets staked. Conventionally the creators of the token would create a dapp to interact with the token. If many such tokens are held within a wallet, the dapp is required to replicate much of the functionality of a wallet.

Instead (or in addition to), the creators of the token choose to create a TokenScript to facilitate interaction with the staked assets. Now, much of that required functionality would be inherited from a hosting wallet such as NFT focus and management (eg transfer calls). The remainder implementation would be written through the TokenScript in a similar way to a Dapp.

In order for the growing number of wallets that support 

An intuitive implementation is the STL office door token. This NFT is minted and transferred to STL employees. The TokenScript attached to the token contract via the `scriptURI()` function contains instructions on how to operate the door interface. This takes the form of:

1. Query for challenge string (random message from IoT interface eg 'Apples-5E3FA1').

2. Receive and display challenge string on Token View, and request 'Sign Personal'.

3. On obtaining the signature of the challenge string, send back to IoT device.

4. IoT device will unlock door if ec-recovered address holds the NFT.

With `scriptURI()` the experience is greatly enhanced as the flow for the user is:

1. Receive NFT.

2. Use authenticated NFT functionality in the wallet immediately.

The project with contract, TokenScript and IoT firmware is in use by Smart Token Labs office door and numerous other installations. An example implementation contract: [ERC-5169 Contract Example](../assets/eip-5169/contract/ExampleContract.sol) and TokenScript:  [ERC-5169 TokenScript Example](../assets/eip-5169/tokenscript/ExampleScript.xml). Links to the firmware and full sample can be found in the associated discussion linked in the header.
The associated TokenScript can be read from the contract using `scriptURI()`.

### Script location

While the most straightforward solution to facilitate specific script usage associated with NFTs, is clearly to store such a script on the smart contract. However, this has several disadvantages: 

1. The smart contract signing key is needed to make updates, causing the key to become more exposed, as it is used more often. 

2. Updates require smart contract interaction. If frequent updates are needed, smart contract calls can become an expensive hurdle.

3. Storage fee. If the script is large, updates to the script will be costly. A client script is typically much larger than a smart contract.

For these reasons, storing volatile data, such as token enhancing functionality, on an external resource makes sense. Such an external resource can be either be  hosted centrally, such as through a cloud provider, or privately hosted through a private server, or decentralized hosted, such as the interplanetary filesystem.

While centralized storage for a decentralized functionality goes against the ethos of web3, fully decentralized solutions may come with speed, price or space penalties. This EIP handles this by allowing the function `ScriptURI` to return multiple URIs, which could be a mix of centralized, individually hosted and decentralized locations.

While this EIP does not dictate the format of the stored script, the script itself could contain pointers to multiple other scripts and data sources, allowing for advanced ways to expand token scripts, such as lazy loading. 
The handling of integrity of such secondary data sources is left dependent on the format of the script.

## Security Considerations

**When a server is involved**

When the client script does not purely rely on connection to a blockchain node, but also calls server APIs,  the trustworthiness of the server API is called into question. This EIP does not provide any mechanism to assert the authenticity of the API access point. Instead, as long as the client script is trusted, it's assumed that it can call any server API in order to carry out token functions. This means the client script can mistrust a server API access point.

**When the scriptURI doesn't contain integrity (hash) information**

We separately authored `Authenticity for Client Script` EIP to guide on how to use digital signatures efficiently and concisely to ensure authenticity and integrity of scripts not stored at a URI which is a digest of the script itself. 

## Copyright

Copyright and related rights waived via [CC0](../LICENSE.md).
