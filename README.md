# 🔴🟡🟢 AMPEL Policy Framework

[![Go Reference](https://pkg.go.dev/badge/github.com/carabiner-dev/policy.svg)](https://pkg.go.dev/github.com/carabiner-dev/policy)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

The AMPEL Policy Framework provides the data structures, tooling, and libraries for defining, distributing, and managing security policies that evaluate software supply chain attestations.

This framework is used by the [AMPEL policy engine](https://github.com/carabiner-dev/ampel) to verify that software artifacts meet specific security and compliance requirements based on [in-toto attestations](https://github.com/in-toto/attestation).

## 🚀 Quick Start

### Installation

```bash
go get github.com/carabiner-dev/policy
```

### Parse and Compile a Policy

```go
package main

import (
    "fmt"
    "github.com/carabiner-dev/policy"
)

func main() {
    // Create a compiler
    compiler := policy.NewCompiler()

    // Compile a policy from a file
    set, pcy, group, err := compiler.CompileFile("my-policy.json")
    if err != nil {
        panic(err)
    }

    if set != nil {
        fmt.Printf("Compiled PolicySet: %s\n", set.GetId())
        fmt.Printf("Contains %d policies\n", len(set.GetPolicies()))
    }
}
```

### Simple Policy Example

```json
{
  "id": "sbom-check",
  "meta": {
    "description": "Verify an SBOM exists"
  },
  "tenets": [
    {
      "id": "has-packages",
      "runtime": "cel@v0",
      "code": "has(sbom.packages) && sbom.packages.size() > 0",
      "predicates": {
        "types": ["https://spdx.dev/Document"]
      },
      "error": {
        "message": "No SBOM found",
        "guidance": "Ensure your build generates an SBOM attestation"
      }
    }
  ]
}
```

## 📖 Documentation

**New to the AMPEL Policy Framework?** Start here:

- **[Overview](docs/overview.md)** - Introduction to concepts and how the framework works
- **[Policy Materials Reference](docs/policy-materials.md)** - Complete guide to Policy, PolicyGroup, and PolicySet
- **[Tooling Reference](docs/tooling.md)** - Parser, Compiler, and Storage Backend documentation

**Technical References:**
- **[Protocol Buffer Definitions](proto/carabiner/policy/v1/policy.proto)** - Schema definitions
- **[Go Package Documentation](https://pkg.go.dev/github.com/carabiner-dev/policy)** - API reference

## ✨ Key Features

### 📦 Policy Materials

Define security requirements using three policy material types:

- **Policy**: Fundamental evaluation unit containing executable checks (tenets)
- **PolicyGroup**: Complex security controls with multiple evaluation strategies
- **PolicySet**: Top-level container bringing policies and groups together

### 🌐 Remote Referencing

Store policies in git repositories or on HTTPS servers, reference them by URI:

```json
{
  "policies": [
    {
      "source": {
        "location": {
          "uri": "git+https://github.com/org/policies@commit-sha#path/to/policy.json"
        }
      }
    }
  ]
}
```

Features:
- Centralized policy management
- Version control with git
- Content integrity verification
- Efficient caching

### 🔄 Flexible Evaluation

Control how policies are evaluated with:

- **Assert Modes**: Require ALL checks to pass (`AND`) or just ONE (`OR`)
- **Enforce Modes**: Block on failures (`ON`) or warn only (`OFF`)
- Mix and match at different levels for sophisticated compliance modeling

### 🔗 Evidence Chaining

Connect attestations across related artifacts:

```json
{
  "chain": [
    {
      "predicate": {
        "type": "https://slsa.dev/provenance/v1",
        "selector": "materials[0].digest.sha1",
        "runtime": "cel@v0"
      }
    }
  ]
}
```

Trace from binaries → images → commits → source code.

### 🎯 Context Values

Parameterize policies for reusability:

```json
{
  "context": {
    "allowed_licenses": {
      "type": "array",
      "required": true,
      "description": "List of approved SPDX license identifiers"
    }
  }
}
```

Same policy, different parameters per organization/project.

### ✅ Identity Verification

Specify expected signers for attestations:

- **Sigstore identities**: OIDC issuer + identity
- **Key-based**: Public key verification
- **Identity references**: Reuse common identities

### 🚄 High Performance

- Parallel remote resource fetching
- Intelligent content caching
- Deduplication by content hash
- Optimized for large policy sets

## 🏗️ Architecture

### Components

This repository contains:

#### 1. **Protocol Buffer Definitions**

The [policy.proto](proto/carabiner/policy/v1/policy.proto) file defines the structure of:
- Policy, PolicyGroup, PolicySet
- Identities, Tenets, Metadata
- Remote references and chain links

Generated Go code is available in [api/v1/](api/v1/).

#### 2. **Parser**

Reads policy files and converts them to structured protobuf objects:
- Supports JSON and HJSON formats
- Handles cryptographic signature envelopes
- Applies default values
- Computes content hashes

[See Parser Documentation →](docs/tooling.md#parser)

#### 3. **Compiler**

Assembles complete policies by resolving remote references:
- Fetches remote policies from git/HTTPS
- Validates and assembles policy structures
- Manages recursive dependencies
- Caches fetched content

[See Compiler Documentation →](docs/tooling.md#compiler)

#### 4. **Storage Backend**

Caching layer for remote content:
- Indexes by hash, URL, and ID
- Deduplicates content
- Optimizes repeated compilations

[See Storage Backend Documentation →](docs/tooling.md#storage-backend)

### Workflow

```
Policy Files (JSON/HJSON)
         ↓
    [Parser]
         ↓
Policy Objects (Protobuf)
         ↓
    [Compiler] ←→ [Storage Backend]
         ↓           ↑
Remote Fetching -----┘
         ↓
Complete PolicySet
         ↓
  [AMPEL Engine]
         ↓
   Evaluation Results
```

## 🧪 Policy Material Elements

### Policy

A policy contains one or more **tenets** (executable checks) evaluated against attestations:

```json
{
  "id": "license-check",
  "meta": {
    "description": "Verify approved licenses",
    "assert_mode": "AND"
  },
  "context": {
    "allowed_licenses": {
      "type": "array",
      "required": true
    }
  },
  "tenets": [
    {
      "id": "check-licenses",
      "runtime": "cel@v0",
      "code": "sbom.packages.all(p, p.license in allowed_licenses)",
      "predicates": {
        "types": ["https://spdx.dev/Document"]
      }
    }
  ]
}
```

**Assert Mode**: `AND` means all tenets must pass, `OR` means at least one must pass.

[Learn more about Policies →](docs/policy-materials.md#policy)

### PolicyGroup

Groups policies into blocks with different evaluation strategies:

```json
{
  "id": "build-verification",
  "blocks": [
    {
      "id": "required-checks",
      "meta": {
        "assert_mode": "AND"
      },
      "policies": [
        // ALL of these must pass
      ]
    },
    {
      "id": "alternative-checks",
      "meta": {
        "assert_mode": "OR"
      },
      "policies": [
        // At least ONE must pass
      ]
    }
  ]
}
```

A PolicyGroup passes when **ALL blocks pass**, enabling complex security controls.

[Learn more about PolicyGroups →](docs/policy-materials.md#policygroup)

### PolicySet

The top-level container combining policies and groups:

```json
{
  "id": "org-policy",
  "meta": {
    "description": "Organizational security policy"
  },
  "common": {
    "identities": [...],
    "context": {...}
  },
  "policies": [...],
  "groups": [...]
}
```

Includes shared identities and context values used by all policies.

[Learn more about PolicySets →](docs/policy-materials.md#policyset)

## 🔧 Usage Examples

### Parse a Policy

```go
parser := policy.NewParser()
pcy, err := parser.ParsePolicyFile("policy.json")
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Policy: %s\n", pcy.GetId())
fmt.Printf("Tenets: %d\n", len(pcy.GetTenets()))
```

### Compile from Remote Location

```go
compiler := policy.NewCompiler()

uri := "git+https://github.com/org/policies@9a70ca49@abc123#policy.json"
set, pcy, group, err := compiler.CompileLocation(uri)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Compiled: %s\n", set.GetId())
```

### Parse with Signature Verification

```go
import "github.com/carabiner-dev/policy/options"

parser := policy.NewParser()

opts := options.WithVerifySignatures(true)
opts = options.WithIdentityStrings([]string{
    "sigstore:https://token.actions.githubusercontent.com:https://github.com/org/repo/.github/workflows/release.yml@refs/tags/v1.0.0",
})

policySet, verification, err := parser.ParseVerifyPolicySetFile(
    "signed-policy.json",
    opts,
)

if verification != nil && verification.GetSignature().GetVerified() {
    fmt.Println("✓ Signature valid")
}
```

### Compile PolicySet with Remote Policies

```go
compiler := policy.NewCompiler()

// PolicySet references remote policies
set, _, _, err := compiler.CompileFile("policyset.json")
if err != nil {
    log.Fatal(err)
}

// Remote policies are fetched, cached, and assembled
for i, p := range set.GetPolicies() {
    fmt.Printf("Policy %d: %s (from %s)\n",
        i,
        p.GetId(),
        p.GetMeta().GetOrigin().GetUri(),
    )
}
```

[More examples in the tooling documentation →](docs/tooling.md#usage-examples)

## 🔐 Supported Runtimes

Tenets support multiple runtimes for executing policy code:

- **CEL (Common Expression Language)**: `cel@v0` (default, recommended)
- **Rego**: `rego@v1` (planned)
- **Cedar**: `cedar@v1` (planned)

CEL is a non-Turing complete expression language designed for safe, fast policy evaluation.

## 🔗 Supported Remote Locations

### Git Repositories (VCS Locators)

```
git+https://github.com/org/repo@commit-sha#path/to/policy.json
git+ssh://git@github.com/org/repo@commit-sha#path/to/policy.json
```

**Best Practice**: Always pin to commit SHAs for reproducibility.

### HTTPS URLs

```
https://policies.example.com/policy.json
```

**Best Practice**: Include content digests for integrity verification:

```json
{
  "source": {
    "location": {
      "uri": "https://example.com/policy.json",
      "digest": {
        "sha256": "abc123..."
      }
    }
  }
}
```

## 🤝 Integration with AMPEL

This framework provides the policy definitions and tooling. To **evaluate** policies against attestations, use the [AMPEL policy engine](https://github.com/carabiner-dev/ampel):

```go
import (
    "github.com/carabiner-dev/policy"
    "github.com/carabiner-dev/ampel"
)

// Compile policy
compiler := policy.NewCompiler()
set, _, _, _ := compiler.CompileFile("policy.json")

// Evaluate with AMPEL
evaluator := ampel.NewEvaluator()
evaluator.LoadPolicySet(set)

result, err := evaluator.Evaluate(attestations, subject, contextValues)
if result.Passed() {
    fmt.Println("✓ Policy passed")
}
```

See the [AMPEL documentation](https://github.com/carabiner-dev/ampel) for details.

## 🧩 Related Projects

- **[AMPEL](https://github.com/carabiner-dev/ampel)** - The policy evaluation engine
- **[policyctl](https://github.com/carabiner-dev/policyctl)** - CLI tool for working with policies
- **[in-toto attestation](https://github.com/in-toto/attestation)** - Attestation format specification

## 📋 Format and Compatibility

Policies are defined using [Protocol Buffers](https://protobuf.dev/) for:
- Strong typing and validation
- Cross-language compatibility
- Efficient serialization
- Clear schema evolution

The framework is designed to work with the [in-toto attestation framework](https://github.com/in-toto/attestation), the industry standard for software supply chain evidence.

## 🧪 Testing

Run tests:

```bash
go test ./...
```

Run specific test suites:

```bash
go test -v -run TestParseLocalPolicies ./...
go test -v -run TestCompileLocalPolicies ./...
```

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Submit a pull request

## 📄 License

This project is Copyright &copy; 2025 by Carabiner Systems, Inc and released under the terms of the [Apache 2.0 license](LICENSE).

## 🙏 Acknowledgments

Built on the [in-toto attestation framework](https://github.com/in-toto/attestation) and inspired by the need for flexible, powerful software supply chain security policies.
