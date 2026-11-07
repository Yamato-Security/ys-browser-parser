// Copyright (C) 2026 Shirofune Security Co., Ltd.
// Copyright (c) 2026 Cyber Experts
//
// This file is changed from Sootmark/plist (https://github.com/Sootmark/plist), whose code
// is under the MIT License or the Apache License 2.0 (LICENSE-MIT, LICENSE-APACHE).
//
// Unless explicitly acquired and licensed from Licensor under another license, the contents of this
// file are subject to the Reciprocal Public License ("RPL") Version 1.5, or subsequent versions as
// allowed by the RPL, and You may not copy or use this file in either source code or executable
// form, except in compliance with the terms and conditions of the RPL.
//
// All software distributed under the RPL is provided strictly on an "AS IS" basis, WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESS OR IMPLIED, AND LICENSOR HEREBY DISCLAIMS ALL SUCH WARRANTIES,
// INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
// PURPOSE, QUIET ENJOYMENT, OR NON-INFRINGEMENT. See the RPL for specific language governing rights
// and limitations under the RPL.

//! Bounds on the work a hostile file can cause.
//!
//! Binary property lists and keyed archives refer to objects by index, so
//! one object can be reached many times. Expanding references into a tree
//! is bounded twice: in depth (which also catches cycles that a writer
//! could hide behind fresh references) and in total size, so that a small
//! file whose arrays all point at the same large array can't expand into
//! gigabytes.

/// The deepest nesting of arrays and dictionaries read. Apple's own files
/// stay within a few dozen levels.
pub(crate) const MAX_DEPTH: usize = 512;

/// Output allowed per byte (binary) or value (archive) of input. Writers
/// share equal strings and numbers between parents, so the expanded tree
/// of an ordinary file is a few times its size; 64 leaves ample room.
const EXPANSION_PER_UNIT: usize = 64;

/// Output allowed whatever the input's size.
const EXPANSION_FLOOR: usize = 1 << 16;

/// The output still allowed: each value costs one, plus its bytes.
pub(crate) struct Budget {
    remaining: usize,
}

impl Budget {
    /// The budget for an input of `units` bytes or values.
    pub(crate) fn for_input(units: usize) -> Self {
        Self {
            remaining: units
                .saturating_mul(EXPANSION_PER_UNIT)
                .saturating_add(EXPANSION_FLOOR),
        }
    }

    /// Takes the cost of one value holding `bytes` bytes, when there is
    /// enough left; `false` (and nothing taken) when there isn't.
    pub(crate) fn spend(&mut self, bytes: usize) -> bool {
        let cost = bytes.saturating_add(1);
        match self.remaining.checked_sub(cost) {
            Some(left) => {
                self.remaining = left;
                true
            }
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn spending_stops_at_the_limit() {
        let mut budget = Budget::for_input(0);
        assert!(budget.spend(EXPANSION_FLOOR - 1));
        assert!(!budget.spend(0));
        assert!(!budget.spend(usize::MAX));
    }
}
