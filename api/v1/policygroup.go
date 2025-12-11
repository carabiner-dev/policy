// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"fmt"

	"github.com/carabiner-dev/signer/key"
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
func (s *PolicyGroup) PublicKeys() ([]key.PublicKeyProvider, error) {
	keys := []key.PublicKeyProvider{}
	for _, id := range s.GetCommon().GetIdentities() {
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
