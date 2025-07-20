use tracing::info;

fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .with_target(false)
        .with_file(true)
        .with_line_number(true)
        .without_time()
        .init();

    info!("Hello, world!");
}