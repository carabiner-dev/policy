// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/carabiner-dev/vcslocator"
	"sigs.k8s.io/release-utils/http"

	api "github.com/carabiner-dev/policy/api/v1"
	"github.com/carabiner-dev/policy/options"
)

const (
	AssertModeAND = "AND"
	AssertModeOR  = "OR"

	EnforceOn  = "ON"
	EnforceOff = "OFF"
)

var ErrUnsupportedLocationURI = errors.New("unsupported policy location")

// NewParser creates a new policy parser
func NewParser() *Parser {
	return &Parser{
		impl: &defaultParserImplementationV1{},
	}
}

// Parser implements methods to read the policy and policy set json files.
// Note that the parser only deals with decoding json. Use the policy compiler
// to assemble policies with external/remote references.
type Parser struct {
	impl parserImplementation
}

// Open opens a Policy or policySet. This function supports remote locations
// (https URLs or VCS locators) and will eventually verify signatures after
// reading and parsing data (still under construction).
func (p *Parser) Open(location string, funcs ...options.ParseOptFn) (set *api.PolicySet, pcy *api.Policy, err error) {
	// Open de PolicySet/Policy data from files or remote locations
	var data []byte
	switch {
	case strings.HasPrefix(location, "git+https://"), strings.HasPrefix(location, "git+ssh://"):
		var b bytes.Buffer
		if err := vcslocator.CopyFile(location, &b); err != nil {
			return nil, nil, fmt.Errorf("copying data from repository: %w", err)
		}
		data = b.Bytes()
	case strings.HasPrefix(location, "https://"):
		data, err = http.NewAgent().Get(location)
	default:
		data, err = os.ReadFile(location)
	}

	if err != nil {
		return nil, nil, fmt.Errorf("opening policy data: %w", err)
	}

	// Parse the read data
	set, pcy, err = p.ParsePolicyOrSet(data, funcs...)
	if err != nil {
		return nil, nil, fmt.Errorf("parsing policy data: %w", err)
	}

	return set, pcy, nil
}

// ParseFile parses a policySet from a file
func (p *Parser) ParsePolicySetFile(path string, funcs ...options.ParseOptFn) (*api.PolicySet, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}

	return p.ParsePolicySet(data, funcs...)
}

// ParsePolicyFile parses a policy from a file
func (p *Parser) ParsePolicyFile(path string, funcs ...options.ParseOptFn) (*api.Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading polciy file: %w", err)
	}

	return p.ParsePolicy(data, funcs...)
}

// ParseSet parses a policy set.
func (p *Parser) ParsePolicySet(policySetData []byte, funcs ...options.ParseOptFn) (*api.PolicySet, error) {
	opts := options.DefaultParseOptions
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}
	// Parse the policy set data
	set, _, err := p.impl.ParsePolicySet(&opts, policySetData)
	if err != nil {
		return nil, fmt.Errorf("parsing policy source: %w", err)
	}
	return set, nil
}

// ParsePolicy parses a policy from its JSON representation or an envelope
func (p *Parser) ParsePolicy(data []byte, funcs ...options.ParseOptFn) (*api.Policy, error) {
	opts := options.DefaultParseOptions
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, err
		}
	}
	pcy, _, err := p.impl.ParsePolicy(&opts, data)
	if err != nil {
		return nil, fmt.Errorf("parsing policy data: %w", err)
	}
	return pcy, nil
}

// ParsePolicyOrSet takes json data and tries to parse a policy or a policy set
// out of it. Returns an error if the JSON data is none.
func (p *Parser) ParsePolicyOrSet(data []byte, funcs ...options.ParseOptFn) (set *api.PolicySet, pcy *api.Policy, err error) {
	opts := options.DefaultParseOptions
	for _, f := range funcs {
		if err := f(&opts); err != nil {
			return nil, nil, err
		}
	}
	var wg sync.WaitGroup
	wg.Add(2)

	var errSet, errPolicy error
	go func() {
		defer wg.Done()
		set, _, errSet = p.impl.ParsePolicySet(&opts, data)
	}()
	go func() {
		defer wg.Done()
		pcy, _, errPolicy = p.impl.ParsePolicy(&opts, data)
	}()

	// Wait for both parsers
	wg.Wait()

	if (set == nil && pcy == nil) || (errSet != nil && errPolicy != nil) {
		return nil, nil, errors.New("unable to parse a policy or policySet from data")
	}
	return set, pcy, nil
}
