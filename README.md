# 🔴🟡🟢 AMPEL Policy Framework

This is the Policy Framework used by the [The Amazing
Multipurpose Policy Engine (and L)](https://github.com/carabiner-dev/ampel) (AMPEL)
policy engine.

The components housed on this repository include:

## Policy and PolicySet Protobuf Definitions

This respository contains the
[protocol buffers definitions](proto/carabiner/policy/v1/policy.proto) for the
AMPEL policies and policy sets. In addition it includes the generated Go code
libraries, including [methods and other convenience functions](api/v1/).

The definitions and libraries depend on the
[in-toto/attestation](https://github.com/in-toto/attestation) protocol buffers
definitions and code.

## Policy Tooling

This repository also contains the policy tooling that
[AMPEL](https://github.com/carabiner-dev/ampel) and 
[policyctl](https://github.com/carabiner-dev/policyctl) depend on. The policy
tooling includes:

### Policy Compiler

The library that compiles the AMPEL policies from possibly distributed sources.

### Policy Fetcher

A high performance utility that fetches policy data from repositories such as
HTTP servers, git repositories, etc.

### Policy Signer

Handles policy signing and verification.

## Copyright

This project is Copyright &copy; by Carabiner Systems, Inc and released under the
terms of the Apache 2.0 license.
