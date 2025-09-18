// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"regexp"
	"strings"
)

// Error implements the Go error interface when verification fails
func (v *Verification) Error() string {
	if !v.GetVerified() && v.GetSignature() != nil {
		return v.GetSignature().GetError()
	}
	return ""
}

// MatchesIdentity returns true if one of the verified signatures matches
// the identity.
func (v *Verification) MatchesIdentity(rawID any) bool {
	id, ok := rawID.(*Identity)
	if !ok {
		return false
	}
	if v.GetSignature() == nil {
		return false
	}

	return v.GetSignature().MatchesIdentity(id)
}

func (v *Verification) GetVerified() bool {
	if v.GetSignature() == nil {
		return false
	}
	return v.GetSignature().GetVerified()
}

// HasIdentity returns true if one of the verifiers matches the passed identity
func (sv *SignatureVerification) MatchesIdentity(id *Identity) bool {
	switch {
	case id.GetSigstore() != nil:
		return sv.MatchesSigstoreIdentity(id.GetSigstore())
	case id.GetKey() != nil:
		return sv.MatchesKeyIdentity(id.GetKey())
	default:
		return false //  This would be an error
	}
}

// HasIdentity returns true if one of the verifiers matches the passed sigstore
// identity.
func (sv *SignatureVerification) MatchesSigstoreIdentity(id *IdentitySigstore) bool {
	// If the identity is missing either the issuer or its ID string, then
	// we reject it.
	if id.GetIdentity() == "" || id.GetIssuer() == "" {
		return false
	}

	// If this is a regexp matcher, compile them
	var regIdentity, regIssuer *regexp.Regexp
	if id.Mode != nil && *id.Mode == SigstoreModeRegexp {
		var err error
		regIdentity, err = regexp.Compile(id.GetIdentity())
		if err != nil {
			return false
		}
		regIssuer, err = regexp.Compile(id.GetIssuer())
		if err != nil {
			return false
		}
	}

	// Check each identity in the verification until one matches.
	for _, signer := range sv.Identities {
		if signer.GetSigstore() == nil {
			continue
		}

		if id.Mode == nil || *id.Mode == SigstoreModeExact {
			if signer.GetSigstore().GetIdentity() == id.GetIdentity() &&
				signer.GetSigstore().GetIssuer() == id.GetIssuer() {
				return true
			}
		} else if *id.Mode == SigstoreModeRegexp {
			if regIdentity.MatchString(signer.GetSigstore().GetIdentity()) &&
				regIssuer.MatchString(signer.GetSigstore().GetIssuer()) {
				return true
			}
		}
	}
	return false
}

// MatchesKeyIdentity returns true if one of the verified signatures was performed
// with the specified key.
func (sv *SignatureVerification) MatchesKeyIdentity(keyIdentity *IdentityKey) bool {
	// Normalize the data
	id := strings.TrimSpace(keyIdentity.GetId())
	data := strings.TrimSpace(keyIdentity.GetData())

	// We need the ID or the key data to match.
	if id == "" && data == "" {
		return false
	}

	// Check each identity in the verification until one matches.
	for _, signer := range sv.Identities {
		signerKeyData := signer.GetKey()
		if signerKeyData == nil {
			continue
		}

		if id != "" && strings.TrimSpace(signerKeyData.GetId()) != id {
			continue
		}

		if data != "" && strings.TrimSpace(signerKeyData.GetData()) != data {
			continue
		}

		// Match
		return true
	}
	return false
}
