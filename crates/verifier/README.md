<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-openid4vp-verifier

Verifier-side OpenID4VP request construction and authorization-response
validation.

The crate is network-free. Signing, holder-binding verification, ZK verification,
clock access, and session storage are injected through explicit traits.
