#!/usr/bin/env bash
# SPDX-FileCopyrightText: Copyright 2025 Carabiner Systems, Inc
# SPDX-License-Identifier: Apache-2.0

set -o errexit
set -o nounset
set -o pipefail

set -o xtrace

# shellcheck source=/dev/null
source hack/common.sh

cloned_repo=0
generated_intoto=1

if [ -d "api/in_toto_attestation" ]; then
  generated_intoto=0
fi

if [ -d "vendor/attestation" ]; then
  echo "Reusing vendored in-toto/attestation directory"
else
  echo "Cloning in-toto/attestation to vendor/"
  mkdir vendor
  git clone --depth=1 https://github.com/in-toto/attestation vendor/attestation
  cloned_repo=1
fi

buf generate

if [ "$cloned_repo" -eq 1 ]; then
  rm -rf vendor
fi

if [ "$generated_intoto" -eq 1 ]; then
  rm -rf api/in_toto_attestation
fi
