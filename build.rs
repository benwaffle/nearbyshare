use std::{env, path::Path};

fn main() {
    let out_dir_env = env::var_os("OUT_DIR").unwrap();
    let out_dir = Path::new(&out_dir_env);
    protobuf_codegen::Codegen::new()
        .out_dir(out_dir)
        .inputs(&["src/proto/device_to_device_messages.proto"])
        .inputs(&["src/proto/offline_wire_formats.proto"])
        .inputs(&["src/proto/securegcm.proto"])
        .inputs(&["src/proto/securemessage.proto"])
        .inputs(&["src/proto/ukey.proto"])
        .inputs(&["src/proto/wire_format.proto"])
        .include("src/proto")
        .run_from_script();
}
