use crate::utils::LETTER_FREQUENCY;
use std::collections::HashMap;
use std::string::FromUtf8Error;

fn score_plaintext(char_count: &mut HashMap<char, f64>) -> f64 {
    let mut score = 0f64;

    for (character, frequency) in LETTER_FREQUENCY.entries() {
        match char_count.get(character) {
            Some(count) => score += (*frequency * count).sqrt(),
            None => continue,
        }
    }

    score
}

pub fn single_byte_xor_cipher(decoded: Vec<u8>) -> Result<(String, f64, u8), FromUtf8Error> {
    let mut key = 0u8;
    let mut score: f64 = 0.0;
    let mut plaintext = String::from("");
    'block: for x in 0..255u8 {
        let mut char_count: HashMap<char, f64> = HashMap::new();
        let decoded_len = decoded.len() as f64;
        let mut decoded = decoded.clone();

        for el in decoded.iter_mut() {
            *el ^= x;

            if (*el < 32 && *el != 9 && *el != 10 && *el != 13) || *el >= 127 {
                continue 'block;
            }

            *(char_count
                .entry((*el as char).to_ascii_lowercase())
                .or_insert(0.0)) += 1.0 / decoded_len;
        }

        let current_score: f64 = score_plaintext(&mut char_count);

        if current_score > score {
            key = x;
            score = current_score;
            plaintext = String::from_utf8(decoded)?;
        }
    }

    Ok((plaintext, score, key))
}
