use crate::utils::hamming_distance;
use crate::utils::LETTER_FREQUENCY;
use hex::FromHexError;
use openssl::error::ErrorStack;
use openssl::symm::Cipher;
use openssl::symm::Crypter;
use openssl::symm::Mode;
use std::collections::HashMap;
use std::collections::HashSet;
use std::string::FromUtf8Error;

pub fn convert_hex_to_base64(data: &str) -> Result<String, FromHexError> {
    let decoded = hex::decode(data)?;
    Ok(base64::encode(&decoded))
}

pub fn fixed_xor(x: &mut [u8], y: &[u8]) {
    assert_eq!(x.len(), y.len());

    for i in 0..x.len() {
        x[i] ^= y[i]
    }
}

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

pub fn repeating_key_xor(key: &[u8], data: &mut [u8]) {
    let key_len = key.len();
    for (i, el) in data.iter_mut().enumerate() {
        *el ^= key[i % key_len];
    }
}

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

pub fn decrypt_aes_ecb_128(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_128_ecb();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None)?;
    let mut out = vec![0; data.len() + cipher.block_size()];
    let mut count = crypter.update(data, &mut out)?;
    count += crypter.finalize(&mut out[count..])?;
    out.truncate(count);

    Ok(out)
}

pub fn detect_aes_ecb_mode(blocks: Vec<Vec<u8>>) -> Option<String> {
    for data in blocks {
        if data.len() % 16 == 0 {
            let mut set: HashSet<&[u8]> = HashSet::new();
            let mut duplicate_blocks = 0;
            for block in data.chunks(16) {
                match set.get(block) {
                    Some(_) => {
                        duplicate_blocks += 1;
                    }
                    None => {
                        set.insert(block);
                    }
                }
            }

            if duplicate_blocks > 0 {
                return Some(hex::encode(data));
            }
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use std::fs;

    #[test]
    fn convert_hex_to_base64_1() {
        assert_eq!(
            Ok(
                "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".into()),
            super::convert_hex_to_base64("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")
        )
    }

    #[test]
    fn fixed_xor_2() {
        let mut x = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
        let y = hex::decode("686974207468652062756c6c277320657965").unwrap();
        super::fixed_xor(&mut x, &y);

        assert_eq!(
            hex::decode("746865206b696420646f6e277420706c6179").unwrap(),
            x
        )
    }

    #[test]
    fn single_byte_xor_cipher_3() {
        let decoded =
            hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
                .unwrap();

        assert_eq!(
            Ok((
                "Cooking MC's like a pound of bacon".into(),
                0.8211192004719269,
                88
            )),
            super::single_byte_xor_cipher(decoded)
        );
    }

    #[test]
    fn detect_single_byte_xor_4() {
        let data = fs::read_to_string("challenge_data/set_one/4.txt").unwrap();
        let lines = data.lines().collect::<Vec<_>>();

        assert_eq!(
            "Now that the party is jumping\n".to_string(),
            super::detect_single_byte_xor(lines)
        );
    }

    #[test]
    fn repeating_key_xor_5() {
        let mut data =
            "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
                .as_bytes()
                .to_vec();

        super::repeating_key_xor("ICE".as_bytes(), &mut data);

        assert_eq!(hex::encode(data), "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f")
    }

    #[test]
    fn break_repeating_key_xor_6() {
        let mut decoded = vec![];

        for line in fs::read_to_string("challenge_data/set_one/6.txt")
            .unwrap()
            .lines()
        {
            decoded.append(&mut base64::decode(line).unwrap())
        }

        let key = String::from("Terminator X: Bring the noise");
        let plaintext = String::from("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n");

        assert_eq!(
            super::break_repeating_key_xor(decoded),
            Ok((key, plaintext))
        )
    }

    #[test]
    fn decrypt_aes_ecb_128_7() {
        let mut decoded = vec![];

        for line in fs::read_to_string("challenge_data/set_one/7.txt")
            .unwrap()
            .lines()
        {
            decoded.append(&mut base64::decode(line).unwrap())
        }

        let plaintext = String::from("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n");

        assert_eq!(
            Ok(plaintext),
            String::from_utf8(
                super::decrypt_aes_ecb_128("YELLOW SUBMARINE".as_bytes(), &decoded).unwrap()
            )
        )
    }

    #[test]
    fn detect_aes_ecb_mode_8() {
        let encoded = fs::read_to_string("challenge_data/set_one/8.txt").unwrap();
        let ecb_mode = String::from("d880619740a8a19b7840a8a31c810a3d08649af70dc06f4fd5d2d69c744cd283e2dd052f6b641dbf9d11b0348542bb5708649af70dc06f4fd5d2d69c744cd2839475c9dfdbc1d46597949d9c7e82bf5a08649af70dc06f4fd5d2d69c744cd28397a93eab8d6aecd566489154789a6b0308649af70dc06f4fd5d2d69c744cd283d403180c98c8f6db1f2a3f9c4040deb0ab51b29933f2c123c58386b06fba186a");
        let blocks = encoded
            .lines()
            .map(|val| hex::decode(val).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(Some(ecb_mode), super::detect_aes_ecb_mode(blocks))
    }
}
