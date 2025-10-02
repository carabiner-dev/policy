// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/collector/envelope"
	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/carabiner-dev/policy/api/v1"
	"github.com/carabiner-dev/policy/options"
)

type parserImplementation interface {
	ParsePolicySet(*options.ParseOptions, []byte) (*v1.PolicySet, attestation.Verification, error)
	ParsePolicy(*options.ParseOptions, []byte) (*v1.Policy, attestation.Verification, error)
}

type defaultParserImplementationV1 struct{}

// ParsePolicySet parses a policy set from a byte slice.
func (dpi *defaultParserImplementationV1) ParsePolicySet(opts *options.ParseOptions, policySetData []byte) (*v1.PolicySet, attestation.Verification, error) {
	// Extract the policy predicate, if any
	policySetData, verification, err := parseEnvelope(opts, policySetData)
	if err != nil {
		return nil, nil, fmt.Errorf("testing for signature envelope: %w", err)
	}

	set := &v1.PolicySet{}
	err = protojson.UnmarshalOptions{
		AllowPartial:   false,
		DiscardUnknown: false,
	}.Unmarshal(policySetData, set)
	if err != nil {
		return nil, verification, fmt.Errorf("parsing policy set source: %w", err)
	}

	if set.GetMeta() == nil {
		set.Meta = &v1.PolicySetMeta{}
	}

	if set.GetMeta().GetEnforce() == "" {
		set.GetMeta().Enforce = EnforceOn
	}

	for _, p := range set.Policies {
		// Don't apply defaults to policies with remote sources
		// They will get their defaults from the remote policy during assembly
		if p.GetSource() != nil {
			continue
		}

		if p.GetMeta() == nil {
			p.Meta = &v1.Meta{}
		}

		if p.GetMeta().GetAssertMode() == "" {
			p.GetMeta().AssertMode = AssertModeAND
		}

		if p.GetMeta().GetEnforce() == "" {
			p.GetMeta().Enforce = EnforceOn
		}
	}
	return set, verification, nil
}

// ParsePolicy parses a policy from a byte slice.
func (dpi *defaultParserImplementationV1) ParsePolicy(opts *options.ParseOptions, policyData []byte) (*v1.Policy, attestation.Verification, error) {
	// Extract the policy when used as a envelope's predicate
	policyData, verification, err := parseEnvelope(opts, policyData)
	if err != nil {
		return nil, nil, fmt.Errorf("testing for signature envelope: %w", err)
	}

	p := &v1.Policy{}
	err = protojson.UnmarshalOptions{}.Unmarshal(policyData, p)
	if err != nil {
		return nil, verification, fmt.Errorf("parsing policy source: %w", err)
	}

	if p.GetMeta() == nil {
		p.Meta = &v1.Meta{}
	}

	if p.GetMeta().GetEnforce() == "" {
		p.GetMeta().Enforce = EnforceOn
	}

	if p.GetMeta().GetAssertMode() == "" {
		p.GetMeta().AssertMode = AssertModeAND
	}

	return p, verification, nil
}

// parseEnvelope parses a policy when wrapped in a cryptographic envelope.
func parseEnvelope(opts *options.ParseOptions, bundleData []byte) ([]byte, attestation.Verification, error) {
	p := envelope.Parsers
	envelopes, err := p.Parse(bytes.NewBuffer(bundleData))
	if err != nil {
		if errors.Is(err, attestation.ErrNotCorrectFormat) {
			return bundleData, nil, nil
		}
		return nil, nil, fmt.Errorf("parsing bundle: %w", err)
	}

	if len(envelopes) == 0 {
		return nil, nil, errors.New("no envelopes found in data")
	}

	// If no signature verification was requested, we can end here.
	if !opts.VerifySignatures {
		return envelopes[0].GetPredicate().GetData(), envelopes[0].GetPredicate().GetVerification(), nil
	}

	// Verify the signatures
	if err := envelopes[0].Verify(opts.PublicKeys); err != nil {
		return nil, nil, fmt.Errorf("verifying policy envelope: %w", err)
	}

	// If the envelope is not signed (verification is nil), then we can end here
	verification := envelopes[0].GetPredicate().GetVerification()
	if verification == nil {
		return envelopes[0].GetPredicate().GetData(), nil, nil
	}

	v, ok := verification.(*v1.Verification)
	if !ok {
		return nil, nil, fmt.Errorf("unsupported verification result type: %T", verification)
	}

	validIds := []*v1.Identity{}
	for _, idstring := range opts.IdentityStrings {
		id, err := v1.NewIdentityFromSlug(idstring)
		if err != nil {
			return nil, nil, fmt.Errorf("parsing id string %q: %w", idstring, err)
		}
		validIds = append(validIds, id)
	}

	// If there were valid identities specified, we mutate the verification
	// results, in other words, white listing here and fail it if needed.
	if len(validIds) > 0 {
		acceptedIds := []*v1.Identity{}
		for _, id := range validIds {
			if v.MatchesIdentity(id) {
				acceptedIds = append(acceptedIds, id)
			}
		}
		v.GetSignature().Identities = acceptedIds

		if len(acceptedIds) == 0 {
			v.GetSignature().Verified = false
			v.GetSignature().Error = fmt.Sprintf("unable to match signer with %d allowed identities", len(validIds))
		}
		verification = v
	}

	return envelopes[0].GetPredicate().GetData(), verification, nil
}
