// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

type ParseOptions struct {
	VerificationOptions
}

var DefaultParseOptions = ParseOptions{
	VerificationOptions: DefaultVerificationOptions,
}

type ParseOptFn func(*ParseOptions) error
