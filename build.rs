use std::{env, path::Path};

fn main() {
    let out_dir_env = env::var_os("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_env);
    protobuf_codegen::Codegen::new()
        .out_dir(out_dir)
        .inputs([
            "src/proto/device_to_device_messages.proto",
            "src/proto/offline_wire_formats.proto",
            "src/proto/securegcm.proto",
            "src/proto/securemessage.proto",
            "src/proto/ukey.proto",
            "src/proto/wire_format.proto",
        ])
        .include("src/proto")
        .run_from_script();
}
