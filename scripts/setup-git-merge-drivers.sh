#!/usr/bin/env bash
# Copyright 2026 Datadog, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -euo pipefail

# Configure git merge drivers for this repository
#
# This script sets up custom merge drivers that are referenced in .gitattributes
# Run this once after cloning the repository to enable automatic conflict resolution
# for generated files.

echo "Configuring git merge drivers..."

# Configure merge driver for LICENSE-3rdparty.csv
# On merge conflicts, this will regenerate the file instead of trying to merge manually
git config merge.generate-licenses.driver "./scripts/generate-3rdparty-licenses.sh && git add LICENSE-3rdparty.csv"
git config merge.generate-licenses.name "Regenerate LICENSE-3rdparty.csv from dependencies"

echo "✓ Git merge drivers configured successfully"
echo ""
echo "The following merge drivers are now active:"
echo "  - LICENSE-3rdparty.csv: Will be regenerated automatically on merge conflicts"
