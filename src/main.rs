/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is dual-licensed under either the MIT license found in the
 * LICENSE-MIT file in the root directory of this source tree or the Apache
 * License, Version 2.0 found in the LICENSE-APACHE file in the root directory
 * of this source tree. You may select, at your option, one of the
 * above-listed licenses.
 */

mod client;
mod cloudflare_client;
mod commands;
mod crypto;
mod keys;
mod mock_client;
mod proto;
mod real_client;
mod types;
mod verification;

use clap::CommandFactory;
use clap::Parser;

#[derive(Parser)]
#[command(name = "mbt", version, about = "Meta Binary Transparency CLI")]
struct Cli {
    #[command(subcommand)]
    command: Option<commands::Commands>,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let use_mock = std::env::var("MBT_USE_MOCK").is_ok();

    let mock;
    let real;
    let client: &dyn client::BtClient = if use_mock {
        mock = mock_client::MockClient;
        &mock
    } else {
        real = real_client::RealClient::new("https://api.facebook.com");
        &real
    };
    let cloudflare = cloudflare_client::CloudflareClient::new();

    match cli.command {
        Some(cmd) => commands::run(cmd, client, &cloudflare),
        None => {
            Cli::command().print_help()?;
            println!();
            Ok(())
        }
    }
}
