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
extern crate thiserror;

pub mod dnsname;
pub mod errors;
pub mod label;
pub mod message;
pub mod record;
pub mod types;
pub mod utils;
pub mod zone;

pub fn version() -> &'static str {
    "v0.1.0"
}
