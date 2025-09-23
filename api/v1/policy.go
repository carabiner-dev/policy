// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"errors"
	"fmt"
	"strings"

	"github.com/carabiner-dev/signer/key"
	"github.com/carabiner-dev/vcslocator"
	intoto "github.com/in-toto/attestation/go/v1"
)

const (
	SigstoreModeExact  string = "exact"
	SigstoreModeRegexp string = "regexp"
)

func (meta *Meta) testsControl(ctrl *Control) bool {
	if meta.GetControls() == nil {
		return false
	}
	for _, c := range meta.GetControls() {
		if ctrl.Class == "" {
			if c.GetId() == ctrl.GetId() {
				return true
			}
		} else {
			if c.GetId() == ctrl.GetId() && c.GetClass() == ctrl.GetClass() {
				return true
			}
		}
	}
	return false
}

func (policy *Policy) TestsControl(ctrl *Control) bool {
	if ctrl == nil {
		return false
	}

	if policy.GetMeta() == nil {
		return false
	}
	return policy.GetMeta().testsControl(ctrl)
}

// GetSourceURL returns the URL to fetch the policy. First, it will try the
// DownloadLocation, if empty returns the UR
func (ref *PolicyRef) GetSourceURL() string {
	if ref.GetLocation() == nil {
		return ""
	}

	if ref.GetLocation().GetDownloadLocation() != "" {
		return ref.GetLocation().GetDownloadLocation()
	}
	return ref.GetLocation().GetUri()
}

// Validate returns an error if the reference is not valid
func (ref *PolicyRef) Validate() error {
	errs := []error{}

	// If the download URL is not a VCS locator, the policy MUST have at least one hash
	if ref.GetLocation() != nil {
		uri := ref.GetLocation().GetUri()
		if uri == "" {
			uri = ref.GetLocation().GetDownloadLocation()
		}

		// Ensure a remote reference hash a hash or digest
		if len(ref.GetLocation().GetDigest()) == 0 {
			// VCS locators can have a commit or a hash
			if strings.HasPrefix(uri, "git+") {
				l := vcslocator.Locator(uri)
				parts, err := l.Parse()
				if err != nil {
					errs = append(errs, fmt.Errorf("parsing VCS locator: %w", err))
				} else if parts.Commit == "" {
					errs = append(errs, errors.New("remoter policies referenced by VCS locator require a digest or commit hash"))
				}
			} else if uri != "" {
				errs = append(errs, errors.New("remote policies referenced by URL require at least one hash"))
			}
		} else {
			for algo := range ref.GetLocation().GetDigest() {
				if _, ok := intoto.HashAlgorithms[algo]; !ok {
					errs = append(errs, fmt.Errorf("unknown algorithm %q in reference digest", algo))
				}
			}
		}
	}

	// TODO Check hash algorithms to be valid (from the intoto catalog)

	return errors.Join(errs...)
}

func (p *Policy) Validate() error {
	errs := []error{}

	for _, i := range p.GetIdentities() {
		if err := i.Validate(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// The following functions allow the policy and policset to implement the predicate
// interface te be able to be wrapped in an intoto statement

// ContextMap compiles the context data values into a map, filling the fields
// with their defaults when needed.
func (p *Policy) ContextMap() map[string]any {
	ret := map[string]any{}
	for label, value := range p.Context {
		if value.Value != nil {
			ret[label] = value.Value.AsInterface()
		} else {
			ret[label] = value.Default.AsInterface()
		}
	}
	return ret
}

// PublicKeys returns any public keys defined in the policy identities
func (p *Policy) PublicKeys() ([]key.PublicKeyProvider, error) {
	keys := []key.PublicKeyProvider{}
	for _, id := range p.GetIdentities() {
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
