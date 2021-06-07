use openssl::{
    error::ErrorStack,
    symm::{Cipher, Crypter, Mode},
};

pub fn aes_128_cbc_crypter(
    key: &[u8],
    iv: &[u8],
    data: &[u8],
    mode: Mode,
) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_128_ecb();
    let mut crypter = Crypter::new(cipher, mode, key, None)?;

    // Important - Crypto noob?
    crypter.pad(false);

    let mut count = 0;
    let mut out = vec![0; data.len() + cipher.block_size()];
    let mut previous_block = iv.to_vec();

    for block in data.chunks(cipher.block_size()) {
        match mode {
            Mode::Encrypt => {
                let mut block = block.to_vec();
                super::challenge_nine::pad_pkcs7(&mut block, cipher.block_size() as u8, 0x4);
                crate::set_one::challenge_two::fixed_xor(&mut block, &previous_block);
                count += crypter.update(&mut block, &mut out[count..])?;
                previous_block = out[count - cipher.block_size()..count].to_vec();
            }
            Mode::Decrypt => {
                let mut block = block.to_vec();
                count += crypter.update(&mut block, &mut out[count..])?;
                crate::set_one::challenge_two::fixed_xor(
                    &mut out[count - cipher.block_size()..count],
                    &previous_block,
                );
                previous_block = block;
            }
        }
    }

    count += crypter.finalize(&mut out[count..])?;
    out.truncate(count);

    Ok(out)
}

#[cfg(test)]
mod tests {

    #[test]
    fn test_encrypt_decrypt_a() {
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
    fn test_encrypt_decrypt_b() {}
}

// A: Encrypted(block_0 ^ IV) + B: Encrypted(block_1 ^ A) + C: Encrypted(block_2 ^ B)
// block_0: Decrypted(A) ^ IV + block_1: Decrypted(B) ^ A + block_2: Decrypted(C) ^ block_1
