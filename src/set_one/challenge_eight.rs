use std::collections::HashSet;

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
