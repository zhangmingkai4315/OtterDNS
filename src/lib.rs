// Strum contains all the trait definitions
extern crate strum;
#[macro_use]
extern crate strum_macros;
extern crate itertools;
extern crate regex;

pub mod dns;

pub fn version() -> &'static str {
    "v0.1.0"
}
