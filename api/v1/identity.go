// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"fmt"
	"strings"

	"github.com/carabiner-dev/signer/key"
)

// NewIdentityFromSlug returns a new identity by parsing a slug string.
//
// There are three kinds of identities supported: sigstore, key and reference.
func NewIdentityFromSlug(slug string) (*Identity, error) {
	itype, identityString, ok := strings.Cut(slug, "::")
	if !ok {
		refId, isRef := strings.CutPrefix(slug, "ref:")
		if isRef {
			return &Identity{Ref: &IdentityRef{Id: refId}}, nil
		}
	}

	switch itype {
	case "sigstore", "sigstore(regexp)":
		issuer, ident, ok := strings.Cut(identityString, "::")
		if !ok {
			return nil, fmt.Errorf("unable to parse sigstore identity from identity string")
		}
		mode := SigstoreModeExact
		if itype == "sigstore(regexp)" {
			mode = SigstoreModeRegexp
		}
		return &Identity{
			Sigstore: &IdentitySigstore{
				Mode:     &mode,
				Issuer:   issuer,
				Identity: ident,
			},
		}, nil
	case "key":
		keyType, keyId, ok := strings.Cut(identityString, "::")
		if !ok {
			return nil, fmt.Errorf("unable to parse key details from identity string")
		}
		return &Identity{
			Key: &IdentityKey{
				Id:   keyId,
				Type: keyType,
			},
		}, nil
	}
	return nil, fmt.Errorf("unable to parse identity from slug string")
}

// Slug returns a string representing the identity
func (i *Identity) Slug() string {
	switch {
	case i.GetSigstore() != nil:
		mode := ""
		if i.GetSigstore().GetMode() == SigstoreModeRegexp {
			mode = "(regexp)"
		}
		return fmt.Sprintf("sigstore%s::%s::%s", mode, i.GetSigstore().GetIssuer(), i.GetSigstore().GetIdentity())
	case i.GetKey() != nil:
		return fmt.Sprintf("key::%s::%s", i.GetKey().GetType(), i.GetKey().GetId())
	case i.GetRef() != nil:
		return fmt.Sprintf("ref:%s", i.GetRef().GetId())
	default:
		return ""
	}
}

// Validate checks the integrity of the identity and returns an error if
// fields are missing or invalid
func (i *Identity) Validate() error {
	errs := []error{}
	typesDefined := []string{}
	if i.GetSigstore() != nil {
		typesDefined = append(typesDefined, "sigstore")
		if i.GetSigstore().GetIssuer() == "" {
			errs = append(errs, fmt.Errorf("sigstore identity has no issuer defined"))
		}

		if i.GetSigstore().GetIdentity() == "" {
			errs = append(errs, fmt.Errorf("sigstore identity has no identifier (email/account) defined"))
		}
	}

	if i.GetKey() != nil {
		typesDefined = append(typesDefined, "key")
		if i.GetKey().GetId() == "" && i.GetKey().GetData() == "" {
			errs = append(errs, errors.New("key identity has to have either id or data set"))
		}
	}

	if i.GetRef() != nil {
		typesDefined = append(typesDefined, "ref")
	}

	if len(typesDefined) == 0 {
		errs = append(errs, errors.New("at least one type of identity must be set (sigstore, key or ref)"))
	}

	if len(typesDefined) > 1 {
		errs = append(errs, fmt.Errorf("only one type of identity can be set at a time (got %v)", typesDefined))
	}
	return errors.Join(errs...)
}

// PublicKey returns the identity public if by parsing the data if set.
func (i *Identity) PublicKey() (key.PublicKeyProvider, error) {
	var data string
	if data = i.GetKey().GetData(); data == "" {
		return nil, nil
	}
	k, err := key.NewParser().ParsePublicKey([]byte(data))
	if err != nil {
		return nil, fmt.Errorf("parsing key: %w", err)
	}
	return k, nil
}
