use openssl::error::ErrorStack;
use openssl::symm::Cipher;
use openssl::symm::Crypter;
use openssl::symm::Mode;

pub fn decrypt_aes_ecb_128(key: &[u8], data: &[u8]) -> Result<Vec<u8>, ErrorStack> {
    let cipher = Cipher::aes_128_ecb();
    let mut crypter = Crypter::new(cipher, Mode::Decrypt, key, None)?;
    let mut out = vec![0; data.len() + cipher.block_size()];
    let count = crypter.update(data, &mut out)?;
    let rest = crypter.finalize(&mut out[count..])?;
    out.truncate(count + rest);

    Ok(out)
}
