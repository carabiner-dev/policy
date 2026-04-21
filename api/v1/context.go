// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"fmt"
	"slices"
)

var ContextTypes = []string{
	ContextTypeBool,
	ContextTypeString,
	ContextTypeInt,
}

const (
	ContextTypeBool   = "bool"
	ContextTypeString = "string"
	ContextTypeInt    = "int"
)

// Validate checks if the context is valid
func (cv *ContextVal) Validate() error {
	if cv.GetType() != "" && !slices.Contains(ContextTypes, cv.GetType()) {
		return fmt.Errorf("invalid context type: %q", cv.GetType())
	}
	if cv.Value != nil && cv.Expression != nil {
		return fmt.Errorf("context value cannot define both `value` and `expression`")
	}
	if cv.Default != nil && cv.Expression != nil {
		return fmt.Errorf("context value cannot define both `default` and `expression`")
	}
	if cv.Expression == nil && cv.GetRuntime() != "" {
		return fmt.Errorf("context value `runtime` is only valid when `expression` is set")
	}
	return nil
}

// Merge merges the values set in cv2 into cv. If values are not set nothing
// is replaced
func (cv *ContextVal) Merge(cv2 *ContextVal) {
	if v := cv2.Default; v != nil {
		cv.Default = v
	}
	if v := cv2.Value; v != nil {
		cv.Value = v
	}
	if v := cv2.Required; v != nil {
		cv.Required = v
	}
	if v := cv2.Expression; v != nil {
		cv.Expression = v
	}
	if v := cv2.Runtime; v != nil {
		cv.Runtime = v
	}
}
