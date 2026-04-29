/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

const NAMESPACES: &[(&str, &str)] = &[(
    "meta.encrypted_backups.fleet_keys.v1",
    "Public keys for encrypted backups (over-the-air)",
)];

pub(crate) fn run() -> anyhow::Result<()> {
    for (name, description) in NAMESPACES {
        println!("{name}\t{description}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_list_is_not_empty() {
        assert!(
            !NAMESPACES.is_empty(),
            "NAMESPACES should contain at least one entry"
        );
    }

    #[test]
    fn namespaces_contains_expected_entries() {
        assert!(
            NAMESPACES
                .iter()
                .any(|(name, _)| *name == "meta.encrypted_backups.fleet_keys.v1"),
            "NAMESPACES should include the encrypted backups fleet keys namespace"
        );
    }
}
