// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	intoto "github.com/in-toto/attestation/go/v1"
)

var (
	_ RemoteReference = &PolicyRef{}
	_ RemoteReference = &PolicyGroupRef{}
)

// RemoteReference is an interface to handle policy and group references
type RemoteReference interface {
	GetId() string
	GetIdentity() *Identity
	GetLocation() *intoto.ResourceDescriptor
	GetSourceURL() string
	GetVersion() int64
	SetVersion(int64)
}
