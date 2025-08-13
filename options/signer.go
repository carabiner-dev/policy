// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package options

type SignerOptions struct{}

var DefaultSignerOptions = SignerOptions{}

type SignerOptFn func(*SignerOptions)
