use openssl::{
    error::ErrorStack,
    symm::{Cipher, Crypter, Mode},
};

pub fn pad_pkcs7(data: &mut Vec<u8>, block_size: u8) {
    let remainder = data.len() % block_size as usize;
    if remainder != 0 {
        let padding_length = block_size - remainder as u8;
        data.extend((0..padding_length as u8).map(|_| padding_length));
    }
}

pub fn unpad_pkcs7(data: &mut Vec<u8>, block_size: u8) {
    let len = data.len();

    if let Some(padded_length) = data.last() {
        let padded_length = *padded_length;
        if len > padded_length as usize && padded_length < block_size {
            let drained = data
                .drain(len - padded_length as usize..)
                .collect::<Vec<_>>();

            if !drained.iter().all(|x| *x == padded_length) {
                data.extend(drained);
            }
        }
    }
}

pub fn aes_128_cbc_crypter(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    mode: Mode,
) -> Result<Vec<u8>, ErrorStack> {
    let mut data = data.to_vec();
    let cipher = Cipher::aes_128_ecb();
    let mut crypter = Crypter::new(cipher, mode, key, None)?;

    // Important - We implement padding ourselves.
    crypter.pad(false);

    match mode {
        Mode::Encrypt => {
            pad_pkcs7(&mut data, cipher.block_size() as u8);
        }
        Mode::Decrypt => {}
    }

    let mut count = 0;
    let mut out = vec![0; data.len() + cipher.block_size()];
    let mut previous_block = iv.to_vec();

    for block in data.chunks(cipher.block_size()) {
        match mode {
            Mode::Encrypt => {
                let mut block = block.to_vec();
                crate::set_one::fixed_xor(&mut block, &previous_block);
                count += crypter.update(&mut block, &mut out[count..])?;
                previous_block = out[count - cipher.block_size()..count].to_vec();
            }
            Mode::Decrypt => {
                let mut block = block.to_vec();
                count += crypter.update(&mut block, &mut out[count..])?;
                crate::set_one::fixed_xor(
                    &mut out[count - cipher.block_size()..count],
                    &previous_block,
                );
                previous_block = block;
            }
        }
    }

    count += crypter.finalize(&mut out[count..])?;

    out.truncate(count);

    match mode {
        Mode::Encrypt => {}
        Mode::Decrypt => {
            unpad_pkcs7(&mut out, cipher.block_size() as u8);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use openssl::symm::Mode;
    use std::fs;

    #[test]
    fn pad_pkcs7_9() {
        let mut data = "YELLOW SUBMARINE".as_bytes().to_vec();
        super::pad_pkcs7(&mut data, 20);

        assert_eq!("YELLOW SUBMARINE\x04\x04\x04\x04".as_bytes(), &data);
    }

    #[test]
    fn test_encrypt_decrypt() {
        let key: [u8; 16] = [
            13, 37, 13, 37, 13, 37, 13, 37, 13, 37, 13, 37, 13, 37, 13, 37,
        ];
        let iv: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];

        let data = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Donec scelerisque posuere nisl, in varius justo porttitor vel. Duis aliquet, est at fringilla laoreet, enim nibh facilisis lacus, quis aliquam magna mauris quis erat. Donec molestie dui et scelerisque vulputate. Cras molestie fermentum lectus, non suscipit mi. Mauris auctor scelerisque nunc eu rhoncus. Ut gravida, erat et suscipit accumsan, lectus purus sodales lorem, vel tincidunt mi metus in leo. Praesent luctus nulla quis est placerat, vitae varius purus sodales. Fusce scelerisque arcu velit, sit amet ullamcorper lectus consequat at. Donec dolor purus, semper a urna imperdiet, pharetra molestie elit. Pellentesque habitant morbi tristique senectus et netus et malesuada fames ac turpis egestas. Nam vel pretium sapien. Suspendisse imperdiet tempor purus. Integer a molestie ligula.".as_bytes();

        let encrypted = super::aes_128_cbc_crypter(&key, &iv, data, super::Mode::Encrypt).unwrap();

        assert_eq!(
            data,
            super::aes_128_cbc_crypter(&key, &iv, &encrypted, super::Mode::Decrypt).unwrap()
        );
    }

    #[test]
    fn aes_cbc_decryption_10() {
        let mut encrypted = vec![];

        for line in fs::read_to_string("challenge_data/set_two/10.txt")
            .unwrap()
            .lines()
        {
            encrypted.append(&mut base64::decode(line).unwrap())
        }

        let iv = &[0u8; 16];

        let decrypted = super::aes_128_cbc_crypter(
            "YELLOW SUBMARINE".as_bytes(),
            iv,
            &encrypted,
            Mode::Decrypt,
        )
        .unwrap();

        assert_eq!(String::from_utf8(decrypted), Ok(String::from("I'm back and I'm ringin' the bell \nA rockin' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that's my DJ Deshay cuttin' all them Z's \nHittin' hard and the girlies goin' crazy \nVanilla's on the mike, man I'm not lazy. \n\nI'm lettin' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse's to the side yellin', Go Vanilla Go! \n\nSmooth 'cause that's the way I will be \nAnd if you don't give a damn, then \nWhy you starin' at me \nSo get off 'cause I control the stage \nThere's no dissin' allowed \nI'm in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n' play \n\nStage 2 -- Yea the one ya' wanna listen to \nIt's off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI'm an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI'm like Samson -- Samson to Delilah \nThere's no denyin', You can try to hang \nBut you'll keep tryin' to get my style \nOver and over, practice makes perfect \nBut not if you're a loafer. \n\nYou'll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I'm comin' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin' \nVanilla Ice is sellin' and you people are buyin' \n'Cause why the freaks are jockin' like Crazy Glue \nMovin' and groovin' trying to sing along \nAll through the ghetto groovin' this here song \nNow you're amazed by the VIP posse. \n\nSteppin' so hard like a German Nazi \nStartled by the bases hittin' ground \nThere's no trippin' on mine, I'm just gettin' down \nSparkamatic, I'm hangin' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n'89 in my time! You, '90 is my year. \n\nYou're weakenin' fast, YO! and I can tell it \nYour body's gettin' hot, so, so I can smell it \nSo don't be mad and don't be sad \n'Cause the lyrics belong to ICE, You can call me Dad \nYou're pitchin' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don't be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you're dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n")));
    }
}

// A: Encrypted(block_0 ^ IV) + B: Encrypted(block_1 ^ A) + C: Encrypted(block_2 ^ B)
// block_0: Decrypted(A) ^ IV + block_1: Decrypted(B) ^ A + block_2: Decrypted(C) ^ block_1
