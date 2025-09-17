// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"github.com/carabiner-dev/signer/key"
)

type VerificationOptions struct {
	PublicKeys      []key.PublicKeyProvider
	IdentityStrings []string
}

var DefaultVerificationOptions = VerificationOptions{}

type VerificationOptFn func(*VerificationOptions)
