// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/vcslocator"
	"sigs.k8s.io/release-utils/http"

	api "github.com/carabiner-dev/policy/api/v1"
	"github.com/carabiner-dev/policy/options"
)

// PolicyOrSet takes a policy or policyset and returns the one that is not nill
func PolicyOrSet(set *api.PolicySet, pcy *api.Policy) any {
	if set != nil {
		return set
	}
	return pcy
}

// CompilerOptions are the settings of the compiler itself.
type CompilerOptions struct {
	// TODO: No remote data
	// TODO: Fail merging on unknown remote tenet ids

	// MaxRemoteRecursion captures the maximum recursion level the
	// compiler will do to fetch remote content. Note that this setting
	// causes exponential requests, so be careful when defining a value.
	MaxRemoteRecursion int
}

var defaultCompilerOpts = CompilerOptions{
	MaxRemoteRecursion: 3,
}

// Compiler is the policy compiler
type Compiler struct {
	Options CompilerOptions
	Store   StorageBackend
	impl    compilerImplementation
}

func NewCompiler() *Compiler {
	opts := defaultCompilerOpts
	return &Compiler{
		Options: opts,
		Store:   newRefStore(),
		impl:    &defaultCompilerImpl{},
	}
}

func (compiler *Compiler) CompileLocation(location string, funcs ...options.OptFn) (*api.PolicySet, *api.Policy, error) {
	set, pcy, _, err := compiler.CompileVerifyLocation(location, funcs...)
	return set, pcy, err
}

// CompileLocaCompileVerifyLocationtion takes a location string and parses a
// policy or PolicySet as read from it. The location will be tested, if it is
// a URL or VCS locator,  it will be retrieved remotely. If its a local file,
// it will be read from disk. Anything else throws an error.
//
// This function variant returns the signature verification.
func (compiler *Compiler) CompileVerifyLocation(location string, funcs ...options.OptFn) (set *api.PolicySet, pcy *api.Policy, ver attestation.Verification, err error) {
	// First, if it looks like a URI, fetch it.
	//
	// TODO(puerco): Figure out a way to not hardcode supported schemes
	if strings.HasPrefix(location, "git+https://") ||
		strings.HasPrefix(location, "git+ssh://") ||
		strings.HasPrefix(location, "https://") {
		return compiler.CompileVerifyRemote(location, funcs...)
	}

	// Try it as a file:
	set, pcy, ver, err = compiler.CompileVerifyFile(location, funcs...)
	if err == nil {
		return set, pcy, ver, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, nil, nil, fmt.Errorf("reading policy file: %w", err)
	}
	return nil, nil, nil, errors.New("unsupported policy location (URI type or file not found)")
}

// CompileRemote reads a policy or policy set from a remote location. The location
// URI can be a git VCS locator using HTTPS or SSH as transport or an HTTPS URL.
func (compiler *Compiler) CompileRemote(uri string, funcs ...options.OptFn) (*api.PolicySet, *api.Policy, error) {
	set, pcy, _, err := compiler.CompileVerifyRemote(uri, funcs...)
	return set, pcy, err
}

// CompileRemote reads a policy or policy set from a remote location. The location
// URI can be a git VCS locator using HTTPS or SSH as transport or an HTTPS URL.
func (compiler *Compiler) CompileVerifyRemote(uri string, funcs ...options.OptFn) (set *api.PolicySet, pcy *api.Policy, ver attestation.Verification, err error) {
	var b bytes.Buffer
	switch {
	case strings.HasPrefix(uri, "git+https://") || strings.HasPrefix(uri, "git+ssh://"):
		err = vcslocator.CopyFile(uri, &b)
	case strings.HasPrefix(uri, "https://"):
		err = http.NewAgent().GetToWriter(&b, uri)
	default:
		return nil, nil, nil, fmt.Errorf("unsupported policy location")
	}
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading policy from remote location: %w", err)
	}
	return compiler.CompileVerify(b.Bytes(), funcs...)
}

// CompileFile reads data from a local file and returns either a policy set or policy.
func (compiler *Compiler) CompileFile(path string, funcs ...options.OptFn) (*api.PolicySet, *api.Policy, error) {
	set, pcy, _, err := compiler.CompileVerifyFile(path, funcs...)
	return set, pcy, err
}

// CompileFile reads data from a local file and returns either a policy set or policy.
func (compiler *Compiler) CompileVerifyFile(path string, funcs ...options.OptFn) (*api.PolicySet, *api.Policy, attestation.Verification, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("reading policy file: %w", err)
	}
	return compiler.CompileVerify(data, funcs...)
}

// CompileVerify compiles a policy, while verifying its signature
func (compiler *Compiler) Compile(data []byte, funcs ...options.OptFn) (*api.PolicySet, *api.Policy, error) {
	set, pcy, _, err := compiler.CompileVerify(data, funcs...)
	return set, pcy, err
}

// CompileVerify is the main method to assemble policies.
//
// Compiling means fetching all the policy references and assembling a
// policy in memory from the fetched data.
func (compiler *Compiler) CompileVerify(data []byte, funcs ...options.OptFn) (set *api.PolicySet, pcy *api.Policy, ver attestation.Verification, err error) {
	opts := options.DefaultCompileOptions
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, nil, nil, err
		}
	}

	// Parse the data to see if it's a policy or PolicySet
	set, pcy, ver, err = NewParser().ParseVerifyPolicyOrSet(data, options.WithParseOptions(&opts.ParseOptions))
	if err != nil {
		return nil, nil, nil, err
	}

	if set == nil && pcy != nil {
		pcy, err := compiler.CompilePolicy(pcy, funcs...)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("compiling policy: %w", err)
		}
		return nil, pcy, ver, nil
	}

	set, err = compiler.CompileSet(set, funcs...)
	return set, nil, ver, err
}

// Compile builds a policy set fetching any remote pieces as necessary
func (compiler *Compiler) CompileSet(set *api.PolicySet, funcs ...options.OptFn) (*api.PolicySet, error) {
	if err := set.Validate(); err != nil {
		return nil, fmt.Errorf("validating policy set: %w", err)
	}

	// Validate PolicySet / Policies
	if err := compiler.impl.ValidateSet(&compiler.Options, set); err != nil {
		return nil, fmt.Errorf("validating policy set: %w", err)
	}

	// Extract and enrich the remote references. This step is expected to return
	// only those refs that point to remote resources and to compound the integrity
	// data (hashes) of the remote resources.
	remoteRefs, err := compiler.impl.ExtractRemoteSetReferences(&compiler.Options, set)
	if err != nil {
		return nil, fmt.Errorf("extracting remote refs: %w", err)
	}

	// Fetch remote resources. This retrieves the remote data but also validates
	// the signatures and/or hashes
	if err := compiler.impl.FetchRemoteResources(
		&compiler.Options, compiler.Store, remoteRefs,
	); err != nil {
		return nil, fmt.Errorf("fetching remote resources: %w", err)
	}

	// Assemble the local policy
	if err := compiler.impl.AssemblePolicySet(&compiler.Options, set, compiler.Store); err != nil {
		return nil, fmt.Errorf("error assembling policy set: %w", err)
	}

	// Validate (with remote parts)
	if err := compiler.impl.ValidateAssembledSet(&compiler.Options, set); err != nil {
		return nil, fmt.Errorf("validating assembled policy: %w", err)
	}

	// Return
	return set, nil
}

// Compile builds a policy set fetching any remote pieces as necessary
func (compiler *Compiler) CompilePolicy(p *api.Policy, funcs ...options.OptFn) (*api.Policy, error) {
	// Validate PolicySet / Policies
	if err := compiler.impl.ValidatePolicy(&compiler.Options, p); err != nil {
		return nil, fmt.Errorf("validating policy: %w", err)
	}

	// Extract and enrich the remote references. This step is expected to return
	// only those refs that point to remote resources and to compound the integrity
	// data (hashes) of the remote resources.
	remoteRefs, err := compiler.impl.ExtractRemotePolicyReferences(&compiler.Options, p)
	if err != nil {
		return nil, fmt.Errorf("extracting remote refs: %w", err)
	}

	// Fetch remote resources. This retrieves the remote data but also validates
	// the signatures and/or hashes
	if err := compiler.impl.FetchRemoteResources(
		&compiler.Options, compiler.Store, remoteRefs,
	); err != nil {
		return nil, fmt.Errorf("fetching remote resources: %w", err)
	}

	// Assemble the local policy
	p, err = compiler.impl.AssemblePolicy(&compiler.Options, p, compiler.Store)
	if err != nil {
		return nil, fmt.Errorf("error assembling policy set: %w", err)
	}

	// Validate (with remote parts)
	if err := compiler.impl.ValidateAssembledPolicy(&compiler.Options, p); err != nil {
		return nil, fmt.Errorf("validating assembled policy: %w", err)
	}

	// Return
	return p, nil
}
