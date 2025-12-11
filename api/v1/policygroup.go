// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"fmt"

	"github.com/carabiner-dev/attestation"
	"github.com/carabiner-dev/signer/key"
	intoto "github.com/in-toto/attestation/go/v1"
	"google.golang.org/protobuf/proto"
)

// GetSourceURL returns the URL to fetch the policy. First, it will try the
// DownloadLocation, if empty returns the UR
func (ref *PolicyGroupRef) GetSourceURL() string {
	if ref.GetLocation() == nil {
		return ""
	}

	if ref.GetLocation().GetDownloadLocation() != "" {
		return ref.GetLocation().GetDownloadLocation()
	}
	return ref.GetLocation().GetUri()
}

func (ref *PolicyGroupRef) SetVersion(v int64) {
	ref.Version = v
}

// Validate checks the consistency of the policy group
func (grp *PolicyGroup) Validate() error {
	return nil
}

// PublicKeys returns any public keys defined in the policy identities
func (grp *PolicyGroup) PublicKeys() ([]key.PublicKeyProvider, error) {
	keys := []key.PublicKeyProvider{}
	for _, id := range grp.GetCommon().GetIdentities() {
		k, err := id.PublicKey()
		if err != nil {
			return nil, fmt.Errorf("parsing key: %w", err)
		}
		if k != nil {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

// GetOrigin returns the coordinates where the predicate data originated from.
func (grp *PolicyGroup) GetOrigin() attestation.Subject {
	if grp.GetMeta() == nil {
		return nil
	}
	return grp.GetMeta().GetOrigin()
}

// SetOrigin sets the origin of the policy. It is designed to match the signature
// of the attestation.Predicate method, but if the argument is a resource descriptor,
// then we will clone it and use its value.
func (grp *PolicyGroup) SetOrigin(origin attestation.Subject) {
	if grp.GetMeta() == nil {
		grp.Meta = &PolicyGroupMeta{}
	}

	rd, ok := origin.(*intoto.ResourceDescriptor)
	if ok {
		msg := proto.Clone(rd)
		nrd, ok := msg.(*intoto.ResourceDescriptor)
		if ok {
			grp.Meta.Origin = nrd
			return
		}
	}

	grp.Meta.Origin = &intoto.ResourceDescriptor{
		Name:   origin.GetName(),
		Uri:    origin.GetUri(),
		Digest: origin.GetDigest(),
	}
}
