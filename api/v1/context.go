// SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
// SPDX-License-Identifier: Apache-2.0

package v1

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
}
