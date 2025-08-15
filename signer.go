// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"io"
	"os"

	"github.com/carabiner-dev/collector/statement/intoto"
	"github.com/carabiner-dev/signer"
	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/carabiner-dev/policy/api/v1"
	"github.com/carabiner-dev/policy/options"
	"github.com/carabiner-dev/policy/predicate"
)

// NewSigner returns a policy signer with the specified options
func NewSigner(funcs ...options.SignerOptFn) *Signer {
	opts := options.DefaultSignerOptions
	for _, fn := range funcs {
		fn(&opts)
	}
	return &Signer{
		Options: opts,
	}
}

// Signer is the policy/policy set signer object.
// Signing is done by wrapping the policies in an in-toto statement and the
// predicate/* wrappers before passing them to the sigstore signer.
type Signer struct {
	Options options.SignerOptions
}

// SignPolicyData signs raw policy data
func (ps *Signer) SignPolicyData(data []byte, w io.Writer, funcs ...options.SignerOptFn) error {
	set, pcy, err := NewParser().ParsePolicyOrSet(data)
	if err != nil {
		return fmt.Errorf("parsing policy material: %w", err)
	}

	// Assemble the in-toto wrapper
	var statement *intoto.Statement
	material := PolicyOrSet(set, pcy)
	switch m := material.(type) {
	case *v1.PolicySet:
		statement = intoto.NewStatement(
			intoto.WithPredicate(&predicate.PolicySet{Parsed: m}),
		)
	case *v1.Policy:
		statement = intoto.NewStatement(
			intoto.WithPredicate(&predicate.Policy{Parsed: m}),
		)
	}

	// OK, data is valid, sign it.
	bundle, err := signer.NewSigner().SignBundle(statement.Predicate.GetData())
	if err != nil {
		return fmt.Errorf("signing policy material: %w", err)
	}

	jsonData, err := protojson.Marshal(bundle)
	if err != nil {
		return fmt.Errorf("marshaling signed policy: %w", err)
	}

	if _, err := w.Write(jsonData); err != nil {
		return fmt.Errorf("writing JSON data to writer: %w", err)
	}

	return nil
}

// SignBundleToFile signs a policy file and writes it to a filename derived from the original.
func (ps *Signer) SignPolicyFile(path string, w io.Writer, funcs ...options.SignerOptFn) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading policy data: %w", err)
	}

	return ps.SignPolicyData(data, w, funcs...)
}
