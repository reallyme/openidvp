<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-openid4vp-types

Typed OpenID4VP request, response, metadata, client identifier, problem-details,
and transaction-data models.

This crate owns protocol wire shapes. It intentionally keeps extensible metadata
and JSON-native presentation values as `serde_json::Value`; adapters and SDK
facades validate those values at their external boundaries.
