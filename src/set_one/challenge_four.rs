use super::challenge_three::single_byte_xor_cipher;

pub fn detect_single_byte_xor(data: Vec<&str>) -> String {
    let mut score: f64 = 0.0;
    let mut plaintext = String::from("");

    for encoded in data {
        if let Ok(decoded) = hex::decode(encoded) {
            match single_byte_xor_cipher(decoded) {
                Ok((temp_plaintext, temp_score, _)) => {
                    if temp_score > score {
                        score = temp_score;
                        plaintext = temp_plaintext;
                    }
                }
                Err(_) => continue,
            };
        }
    }

    plaintext
}
