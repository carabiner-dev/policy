// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"fmt"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/signer/key"
	"google.golang.org/protobuf/encoding/protojson"
)

func (set *PolicySet) Validate() error {
	errs := []error{}
	for _, p := range set.GetPolicies() {
		if err := p.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// GetOrigin returns the coordinates where the predicate data originated when
// the policyset is wrapped in an attestation. At some point this should return
// the original repo where the set was read from.
func (set *PolicySet) GetOrigin() attestation.Subject {
	return nil
}

func (set *PolicySet) SetOrigin(attestation.Subject) {
}

func (set *PolicySet) SetType(attestation.PredicateType) error {
	return nil
}

func (set *PolicySet) GetType() attestation.PredicateType {
	return attestation.PredicateType("") // TODO: Predicate type
}

// SetVerification gets the signature verification data from the envelope
// parser before discarding the envelope. This is supposed the be stored
// for later retrieval.
// Note: Currently NOOP.
func (set *PolicySet) SetVerification(attestation.Verification) {
}

// GetVerification returns the signature verification generated from the
// envelope parser. The verification may contain details about the integrity,
// identity and signature guarding the PolicySet.
func (set *PolicySet) GetVerification() attestation.Verification {
	return nil
}

// GetParsed returns the PolicySet go struct.
func (set *PolicySet) GetParsed() any {
	return set
}

// GetData returns the policy set data marshaled as json.
func (set *PolicySet) GetData() []byte {
	data, err := protojson.Marshal(set)
	if err != nil {
		return nil
	}
	return data
}

// ContextMap compiles the context data values into a map, filling the fields
// with their defaults when needed.
func (s *PolicySet) ContextMap() map[string]any {
	ret := map[string]any{}
	for label, value := range s.GetCommon().GetContext() {
		if value.Value != nil {
			ret[label] = value.Value.AsInterface()
		} else {
			ret[label] = value.Default.AsInterface()
		}
	}
	return ret
}

// PublicKeys returns any public keys defined in the policy identities
func (s *PolicySet) PublicKeys() ([]key.PublicKeyProvider, error) {
	keys := []key.PublicKeyProvider{}
	for _, id := range s.GetCommon().GetIdentities() {
		k, err := id.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("parsing key: %w", err)
		}
		keys = append(keys, k)
	}
	return keys, nil
}
