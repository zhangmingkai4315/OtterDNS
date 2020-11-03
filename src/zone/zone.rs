use crate::dns::record::{ResourceRecord};
pub enum ParseZoneFileErr{
    FileNotExist(String),
    ReadFileError(String),
    ParseZoneDataError
}

#[derive(Debug)]
pub struct Zone{
    filepath: String,
    name: String,
    data: Vec<ResourceRecord>,
}

impl<'a> Zone{
    pub fn new(filepath: &str, name:&str)->Zone{
        Zone{
            filepath: filepath.to_owned(),
            name: name.to_owned(),
            data: vec![],
        }
    }

    pub fn parse_zone_file(&mut self)->Result<(),ParseZoneFileErr>{

        Err(ParseZoneFileErr::ParseZoneDataError)
    }

}

#[cfg(test)]
mod test{
// use super::*;
// use crate::zone::zone::zone::Zone;
//
// #[test]
// fn test_parse_zone_file(){
//     let mut zone = Zone::new("notexist","com");
//     assert_eq!(zone.parse_zone_file().is_err(), true);
// }
}