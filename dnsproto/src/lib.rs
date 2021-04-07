// Strum contains all the trait definitions
extern crate strum;
#[macro_use]
extern crate strum_macros;
extern crate itertools;
extern crate regex;
#[macro_use]
extern crate num_enum;
#[macro_use]
extern crate nom;
extern crate rand;
extern crate thiserror;

pub mod dnsname;
pub mod edns;
pub mod label;
pub mod message;
pub mod meta;
pub mod qtype;
pub mod record;
pub mod utils;
pub mod zone;

pub fn version() -> &'static str {
    "v0.1.0"
}
