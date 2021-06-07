use hex::FromHexError;

pub fn convert_hex_to_base64(data: &str) -> Result<String, FromHexError> {
    let decoded = hex::decode(data)?;
    Ok(base64::encode(&decoded))
}
