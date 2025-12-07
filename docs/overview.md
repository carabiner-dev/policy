# AMPEL Policy Framework - Overview

## What is the AMPEL Policy Framework?

The AMPEL Policy Framework is a system for defining, distributing, and managing security policies that evaluate software supply chain attestations. It provides the data structures and tooling used by the [AMPEL policy engine](https://github.com/carabiner-dev/ampel) to verify that software artifacts meet specific security and compliance requirements.

Think of it as a language for expressing "rules about software" - rules that can check whether your code was built securely, signed by the right people, or contains approved dependencies.

## Core Concepts

### Policy Materials

The framework defines three types of **policy materials** - the building blocks for expressing security requirements:

#### 1. **Policy**

A Policy is the fundamental unit of evaluation. It contains one or more **tenets** (individual checks) that are evaluated against attestations (signed evidence about software artifacts).

**Example**: A policy might check that an SBOM (Software Bill of Materials) exists and contains only approved licenses.

- Contains metadata (description, version, enforcement mode)
- Defines expected signer identities for the attestations being checked
- Lists one or more tenets with executable code
- Specifies an **assert mode**: must ALL tenets pass (AND) or just ONE (OR)?

#### 2. **PolicyGroup**

A PolicyGroup models complex security controls by organizing multiple policies into logical blocks. Each block can have different evaluation strategies.

**Example**: A security control that requires EITHER (two passing SLSA checks) OR (one passing signature verification).

- Contains multiple **PolicyBlocks**
- Each block groups policies and has its own **assert mode**
- The group passes when ALL its blocks pass
- Acts as a single atomic unit at the PolicySet level

**Why use PolicyGroups?** They allow you to model sophisticated security requirements with multiple alternative paths to compliance. One block might require ALL policies to pass (strict checking), while another offers alternative approaches where just ONE policy must pass.

#### 3. **PolicySet**

A PolicySet is the top-level container that brings everything together. It's generally what you load and execute with the AMPEL engine.

**Example**: A complete organizational security policy that includes SBOM checks, vulnerability scanning requirements, and build provenance verification.

- Contains policies and/or policy groups
- Defines common elements (shared identities, context values) used by all policies
- Can reference remote policies/groups from git repositories or HTTPS URLs
- Includes an optional evidence chain specification for multi-artifact verification

## How It Works: From Definition to Evaluation

### 1. **Define Your Policies**

Write policies in JSON (or HJSON) format, specifying:
- What you're checking (tenets with executable code)
- Who should have signed the evidence (identities)
- How strict the checking should be (assert modes, enforce modes)

### 2. **Parse and Compile**

The **Parser** reads your JSON/HJSON files and converts them to structured policy objects. The **Compiler** then:
- Fetches any remotely-referenced policies from git repositories or HTTPS URLs
- Assembles all pieces into a complete, executable policy structure
- Validates the final structure for correctness

### 3. **Execute with AMPEL**

The AMPEL policy engine receives:
- Your compiled PolicySet
- Attestations (signed evidence) about the software being verified
- Runtime context values (parameters like allowed license IDs)

It then evaluates your policies and returns pass/fail results.

## Key Features

### Remote Referencing

Policies can reference other policies stored remotely in git repositories or on HTTPS servers. This enables:
- **Centralized policy management**: Store organizational policies in a git repo
- **Version control**: Pin to specific commits or tags
- **Reusability**: Share common policies across teams
- **Integrity verification**: Validate content hashes to ensure policies haven't been tampered with

Example reference:
```json
{
  "source": {
    "location": {
      "uri": "git+https://github.com/org/policies@commit-sha#path/to/policy.json"
    }
  }
}
```

### Context Values

Make policies reusable by parameterizing them with runtime values:

```json
{
  "context": {
    "allowed_license": {
      "type": "string",
      "required": true,
      "description": "SPDX license identifier to allow"
    }
  }
}
```

When running AMPEL, provide the value via CLI flags, environment variables, or JSON files.

### Flexible Evaluation Modes

- **Assert Modes**: Control whether ALL checks must pass (AND) or just ONE (OR)
- **Enforce Modes**: Decide if failures should block (ON) or just warn (OFF)

Mix and match these at different levels to model complex compliance requirements.

### Evidence Chaining

Sometimes evidence about an artifact exists in attestations about related artifacts. For example, when verifying a binary, build information might be in attestations about the git commit it came from.

**Chain Links** let you connect attestations by extracting subject identifiers from predicates, forming a chain of evidence from artifact to artifact.

## The Compiler and Parser

### Parser

The Parser handles the low-level work of reading policy files:
- Supports both JSON and HJSON (more human-friendly JSON with comments)
- Can read from local files, HTTPS URLs, or git repositories
- Optionally verifies cryptographic signatures on policy files
- Converts policy data into structured protobuf objects

### Compiler

The Compiler assembles complete, executable policies:
- Takes parsed policies and resolves all remote references
- Fetches remote policy materials in parallel for performance
- Uses a storage backend to cache fetched content (avoiding duplicate downloads)
- Validates the assembled policy structure
- Returns a fully-resolved PolicySet ready for evaluation

**The compilation process**:
1. Parse the input policy/set/group
2. Extract all remote references
3. Fetch remote content (cached if already retrieved)
4. Assemble remote pieces into the local structure
5. Validate the complete, assembled result

## Format and Compatibility

Policies are defined using [Protocol Buffers](proto/carabiner/policy/v1/policy.proto), ensuring:
- Strong typing and validation
- Cross-language compatibility
- Efficient serialization
- Clear evolution path for future versions

The framework is designed to work with the [in-toto attestation framework](https://github.com/in-toto/attestation), the industry standard for software supply chain evidence.

## Next Steps

- **[Policy Materials Reference](policy-materials.md)**: Deep dive into Policy, PolicyGroup, and PolicySet structures
- **[Tooling Reference](tooling.md)**: Detailed documentation on the Parser, Compiler, and Storage Backend
- **[AMPEL Engine](https://github.com/carabiner-dev/ampel)**: The policy evaluation engine that uses these policy materials
