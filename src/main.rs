extern crate otterlib;
extern crate strum;
#[macro_use]
extern crate strum_macros;

use otterlib::version;

fn main() {
    println!("OtterDNS:{}", version());
}
