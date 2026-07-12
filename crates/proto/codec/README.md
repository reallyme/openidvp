<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-openid4vp-proto-codec

Mappings between generated OpenID4VP protobuf messages and Rust domain types.

The codec is strict at the boundary: missing fields, invalid enum values, and
malformed JSON payloads return typed errors.
