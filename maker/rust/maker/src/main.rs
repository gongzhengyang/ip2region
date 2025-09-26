use clap::Parser;
use maker::{Command, Maker, Result};

/// Ip2Region database structure
/// See https://github.com/lionsoul2014/ip2region/blob/master/maker/golang/xdb/maker.go
fn main() -> Result<()>{
    tracing_subscriber::fmt::init();

    let cmd = Command::parse();
    let mut maker = Maker::new(cmd.ip_version, cmd.index_policy, &cmd.src, &cmd.dst, cmd.filter_fields)?;
    maker.start()?;

    Ok(())
}
