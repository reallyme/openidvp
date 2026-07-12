<!--
SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved

SPDX-License-Identifier: Apache-2.0
-->

# reallyme-openid4vp-runtime

Framework-neutral OpenID4VP runtime handlers and Connect service builders.

Hosts inject signing, decryption, storage, clocks, holder-binding verification,
and ZK verification. The runtime routes protocol endpoints without owning app
state or network policy.
