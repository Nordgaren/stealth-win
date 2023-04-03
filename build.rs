mod build_src;

use crate::build_src::resource_gen::ResourceGenerator;
use std::env;

fn main() {
    // Don't run this if CARGO_CHECK is set in the environment variables.
    // Helps VS Code users.
    match env::var("CARGO_CHECK") {
        Ok(_) => {
            return;
        }
        Err(_) => {}
    }
    // Get the out dir and pass it into the generator.
    let out_dir = env::var("OUT_DIR").unwrap();
    let mut gen = ResourceGenerator::new(out_dir);
    // Build the resource file
    gen.build_resource_file();
    // Builds src/consts.rs for use in the actual application
    gen.build_consts_file();
    // Build the resources files for embedding.
    gen.build_pe_embed_files();
    // set the newly generated resource into the exe.
    gen.set_pe_resource_file();
}
