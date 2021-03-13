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

pub mod types;
pub mod errors;
pub mod record;
pub mod utils;
pub mod zone;
pub mod label;
pub mod message;

pub fn version() -> &'static str {
    "v0.1.0"
}
