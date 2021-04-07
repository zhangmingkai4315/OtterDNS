use crate::rb_storage::RBTreeNode;
use dnsproto::zone::{ZoneFileParser, ZoneReader};
use otterlib::errors::{OtterError, StorageError};

fn load_zone_from_disk(
    file: &str,
    default_origin: Option<String>,
) -> Result<RBTreeNode, OtterError> {
    let mut zone = RBTreeNode::new_root();
    let parser = ZoneFileParser::new(file)?;
    // read f
    let zone_reader = ZoneReader::new(parser, default_origin);
    for item in zone_reader {
        match item {
            Ok(rr) => {
                // insert rr record to zone node.
                zone.insert_rr(rr)?
            }
            Err(err) => eprintln!("{:?}", err),
        }
    }
    Ok(zone)
}

#[cfg(test)]
mod test {
    use crate::sync::load_zone_from_disk;

    #[test]
    fn test_load_zone_from_disk() {
        let test_zone_file = "./test/example.zone";
        match load_zone_from_disk(test_zone_file, None) {
            Ok(_) => {}
            Err(err) => {
                eprintln!("{:?}", err);
            }
        };
    }
}
