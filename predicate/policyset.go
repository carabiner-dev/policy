// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package predicate

import (
	"github.com/carabiner-dev/attestation"
	"google.golang.org/protobuf/encoding/protojson"

	v1 "github.com/carabiner-dev/policy/api/v1"
)

const PolicySetPredicateType attestation.PredicateType = "https://carabiner.dev/ampel/policyset/v0"

// PolicySet (predicate.Policy) is a wrapper around the policySet proto
// message that implements the ampel attestation predicate interface.
type PolicySet struct {
	Parsed       *v1.PolicySet
	Data         []byte
	origin       attestation.Subject
	verification attestation.Verification
}

// GetOrigin returns the coordinates where the predicate data originated when
// the policyset is wrapped in an attestation. At some point this should return
// the original repo where the policy was read from.
func (set *PolicySet) GetOrigin() attestation.Subject {
	return set.origin
}

func (set *PolicySet) SetOrigin(origin attestation.Subject) {
	set.origin = origin
}

func (set *PolicySet) SetType(attestation.PredicateType) error {
	return nil
}

func (set *PolicySet) GetType() attestation.PredicateType {
	return PolicySetPredicateType
}

// SetVerification gets the signature verification data from the envelope
// parser before discarding the envelope. This is supposed the be stored
// for later retrieval.
func (set *PolicySet) SetVerification(verification attestation.Verification) {
	set.verification = verification
}

// GetVerification returns the signature verification generated from the
// envelope parser. The verification may contain details about the integrity,
// identity and signature guarding the PolicySet.
func (set *PolicySet) GetVerification() attestation.Verification {
	return set.verification
}

// GetParsed returns the Go PolicySet object.
func (set *PolicySet) GetParsed() any {
	if set.Parsed == nil && set.Data != nil {
		newset := &v1.PolicySet{}
		if err := protojson.Unmarshal(set.Data, newset); err == nil {
			set.Parsed = newset
		}
	}
	return set.Parsed
}

// GetData returns the PolicySet data serialized as JSON.
func (set *PolicySet) GetData() []byte {
	if set.Data != nil {
		return set.Data
	}

	data, err := protojson.Marshal(set.Parsed)
	if err != nil {
		return nil
	}
	set.Data = data
	return data
}
