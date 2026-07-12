// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

#![no_main]

use libfuzzer_sys::fuzz_target;
use reallyme_openid4vp_types::{
    canonical_transaction_data_bytes, canonicalize_json, TransactionData, TransactionDataHash,
};

fuzz_target!(|data: &[u8]| {
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = canonicalize_json(&value);
    }
    if let Ok(transaction_data) = serde_json::from_slice::<TransactionData>(data) {
        if let Ok(canonical) = canonical_transaction_data_bytes(&transaction_data) {
            let _ = TransactionDataHash::sha256(&canonical);
        }
        let _ = TransactionDataHash::sha256_transaction_data(&transaction_data);
    }
});
