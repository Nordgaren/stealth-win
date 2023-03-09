use std::env;
use winresource::WindowsResource;

include!("build_src/resource_gen.rs");
#[path = "src/hash.rs"]
mod hash;
#[path = "src/consts.rs"]
mod consts;

fn main() {
    let mut gen = ResourceGenerator::new();
    //build the resource file
    gen.build_resource_file();
    //builds src/consts.rs for use in the actual application
    gen.build_consts_file();
    //build the resources files.
    build_pe_resources_file();
    //embed the newly generated resource into the exe.
    embed_pe_resource_file();
}

fn build_pe_resources_file() {
    fs::write(
        "rsrc/resources.h",
        format!("#define PAYLOAD_ID {}\n", RESOURCE_ID),
    )
    .expect("Could not write resources.h file.");

    fs::write(
        "rsrc/resources.rc",
        format!(
            "#include \"resources.h\"\nPAYLOAD_ID RCDATA {}\n",
            RESOURCE_NAME
        ),
    )
    .expect("Could not write resources.rc file.");
}

fn embed_pe_resource_file() {
    if env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = WindowsResource::new();
        res.set_resource_file("rsrc/resources.rc");
        res.compile().expect("Could not compile pe resource.");
    }
}
