// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

import "errors"

// ParseOptions control how the parses processes data
type ParseOptions struct {
	VerificationOptions
	VerifySignatures bool
}

var DefaultParseOptions = ParseOptions{
	VerificationOptions: DefaultVerificationOptions,
	VerifySignatures:    true,
}

// WithParseOptions replaces all parse options with a new set
func WithParseOptions(newopts *ParseOptions) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.IdentityStrings = newopts.IdentityStrings
			o.PublicKeys = newopts.PublicKeys
			o.VerificationOptions = newopts.VerificationOptions
			o.VerifySignatures = newopts.VerifySignatures
		case *CompileOptions:
			o.ParseOptions = *newopts
		default:
			return ErrUnsupportedOptionsType
		}
		return nil
	}
}

// WithVerifySignatures controls is policy signatures are verified when parsed
func WithVerifySignatures(doVerify bool) OptFn {
	return func(opts Options) error {
		switch o := opts.(type) {
		case *ParseOptions:
			o.VerifySignatures = doVerify
		case *CompileOptions:
			o.VerifySignatures = doVerify
		default:
			return errors.New("unsupported options type")
		}
		return nil
	}
}
