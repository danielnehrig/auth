use failure::Error;

fn main() -> Result<(), Error> {
    tonic_build::configure()
        .build_server(true)
        .compile(&["proto/auth.proto"], &["googleapis", "proto"])
        .unwrap_or_else(|e| panic!("Failed to compile protos {:?}", e));

    Ok(())
}
