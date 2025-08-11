// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"

	ampel "github.com/carabiner-dev/ampel/pkg/api/v1"
	"github.com/carabiner-dev/ampel/pkg/attestation"
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

func (set *PolicySet) SetVerification(*ampel.Verification) {
}

func (set *PolicySet) GetVerification() *ampel.Verification {
	return nil
}

func (set *PolicySet) GetParsed() any {
	return set
}

// GetData returns thevsa
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
