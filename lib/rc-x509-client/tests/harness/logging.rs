use tracing_subscriber::EnvFilter;

/// Install a [`tracing`] subscriber that writes event logs to stdout for the
/// duration of the test process.
pub(crate) fn init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("debug")))
        .with_test_writer()
        .try_init();
}
