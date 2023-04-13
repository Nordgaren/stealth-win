mod build_src;

use crate::build_src::resource_gen::ResourceGenerator;
use std::env;


fn main() {
    // Don't run this if STEALTH_NO_BUILD_SCRIPT is set in the environment variables.
    // Helps anyone who runs Cargo Check on the fly with their editor that can also
    // set environment variables.
    match env::var("STEALTH_NO_BUILD_SCRIPT") {
        Ok(_) => {
            return;
        }
        _ => {}
    }

    // Get the out dir and pass it into the generator.
    let out_dir = env::var("OUT_DIR").unwrap();
    ResourceGenerator::new(out_dir)
        // Build the resource file
        .build_resource_file()
        // Builds src/consts.rs for use in the actual application
        .build_consts_file()
        // Build the resource header files for embedding.
        .build_resource_headers()
        // Set the newly generated resource and compile for being linked to the final exe.
        .build();
}
