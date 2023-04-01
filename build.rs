use std::env;
use winresource::WindowsResource;

include!("build_src/resource_gen.rs");

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let mut gen = ResourceGenerator::new(out_dir);
    //build the resource file
    gen.build_resource_file();
    //builds src/consts.rs for use in the actual application
    gen.build_consts_file();
    //build the resources files.
    build_pe_resources_file(gen.get_out_dir());
    //embed the newly generated resource into the exe.
    embed_pe_resource_file(gen.get_out_dir());
}

fn build_pe_resources_file(out_dir: &str) {
    fs::write(
        format!("{out_dir}/resources.h"),
        format!("#define PAYLOAD_ID {}\n", RESOURCE_ID),
    )
    .expect("Could not write resources.h file.");

    fs::write(
        format!("{out_dir}/resources.rc"),
        format!(
            "#include \"resources.h\"\nPAYLOAD_ID RCDATA {}\n",
            RESOURCE_NAME
        ),
    )
    .expect("Could not write resources.rc file.");
}

fn embed_pe_resource_file(out_dir: &str) {
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = WindowsResource::new();
        res.set_resource_file(&format!("{out_dir}/resources.rc"));
        res.compile().expect("Could not compile pe resource.");
    }
}
