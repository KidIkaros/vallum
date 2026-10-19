// SPDX-License-Identifier: Apache-2.0

//! `vallum import-bundle`: unpack a client bundle file.

use std::path::PathBuf;

use clap::Args;

use crate::Error;

#[derive(Debug, Args)]
pub struct ImportArgs {
    /// The `.vallum-bundle` file to import.
    #[arg(value_name = "FILE")]
    pub bundle: PathBuf,

    /// Directory for the config and key (default: current directory).
    #[arg(long, default_value = ".", value_name = "DIR")]
    pub output_dir: PathBuf,

    /// Overwrite an existing config or key.
    #[arg(long)]
    pub force: bool,
}

pub fn import(args: &ImportArgs) -> Result<(), Error> {
    let bundle = crate::bundle::read(&args.bundle).map_err(Error::Usage)?;
    let imported =
        crate::bundle::import(&bundle, &args.output_dir, args.force).map_err(Error::Usage)?;
    println!("config {}", imported.config.display());
    println!("key    {}", imported.key.display());
    Ok(())
}
