use super::challenge_five::repeating_key_xor;
use super::challenge_three::single_byte_xor_cipher;
use crate::utils::hamming_distance;
use std::string::FromUtf8Error;

pub fn break_repeating_key_xor(data: Vec<u8>) -> Result<(String, String), FromUtf8Error> {
    let mut distances: Vec<(usize, f64)> = vec![];
    for x in 2..=40 {
        let mut total_distance = 0f64;
        let blocks = data.chunks(x).take(4).collect::<Vec<_>>();

        for i in 0..(blocks.len() - 1) {
            total_distance += hamming_distance(blocks[i], blocks[i + 1]) / x as f64
        }

        let distance = total_distance / blocks.len() as f64;

        distances.push((x, distance));
    }

    distances.sort_unstable_by(|a, b| a.1.partial_cmp(&b.1).unwrap());

    let mut total_score = 0f64;
    let mut xor_key = String::from("");
    let mut plaintext = String::from("");

    for (key_size, _) in distances.iter().take(3) {
        let blocks = data.chunks(*key_size).collect::<Vec<_>>();

        let mut single_byte_blocks: Vec<Vec<u8>> = (0..*key_size).map(|_| vec![]).collect();

        for block in blocks {
            for (i, el) in block.iter().enumerate() {
                single_byte_blocks[i].push(*el);
            }
        }

        let mut key = vec![];
        let mut current_score = 0f64;

        for block in single_byte_blocks {
            if let Ok((_, score, key_component)) = single_byte_xor_cipher(block) {
                current_score += score;
                key.push(key_component);
            }
        }

        let mut data = data.to_vec();

        repeating_key_xor(&key, &mut data);

        if current_score > total_score {
            total_score = current_score;
            xor_key = String::from_utf8(key)?;
            plaintext = String::from_utf8(data)?;
        }
    }

    Ok((xor_key, plaintext))
}
