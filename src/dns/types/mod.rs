mod a;
mod aaaa;
mod soa;


trait BinaryConverter: Sized{
    type Err;
    fn from_binary(data: &[u8]) -> Result<Self, Self::Err>;
    fn to_binary(&self) -> Result<Vec<u8>, Self::Err>;
}