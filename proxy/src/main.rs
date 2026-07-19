use box_proxy::config::{check_config, Paths};
use box_proxy::proxy::run;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("box_proxy=info,warn")),
        )
        .with_writer(std::io::stderr)
        .init();

    let args: Vec<String> = std::env::args().skip(1).collect();

    if args.iter().any(|a| a == "-h" || a == "--help") {
        print_help();
        return;
    }
    if args.iter().any(|a| a == "-V" || a == "--version") {
        println!("box-proxy {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    let paths = Paths::from_env();

    if args.iter().any(|a| a == "--check-config") {
        match check_config(&paths) {
            Ok(summary) => {
                print!("{summary}");
                std::process::exit(0);
            }
            Err(err) => {
                eprintln!("box-proxy: check-config failed: {err}");
                std::process::exit(1);
            }
        }
    }

    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(err) => {
            eprintln!("box-proxy: failed to start runtime: {err}");
            std::process::exit(1);
        }
    };

    if let Err(err) = runtime.block_on(run(paths)) {
        eprintln!("box-proxy: {err}");
        std::process::exit(1);
    }
}

fn print_help() {
    println!(
        "box-proxy \u{2014} box egress MITM forward proxy

USAGE:
    box-proxy [--check-config]

FLAGS:
    --check-config   Load allowlist + secrets.json + CA from the configured
                     paths, validate them, print a summary, and exit non-zero
                     on error. No traffic is served.
    -h, --help       Print this help.
    -V, --version    Print the version.

ENVIRONMENT (defaults in parentheses):
    BOX_PROXY_ADDR         listen address ({})
    BOX_ALLOWLIST_GLOBAL   global allowlist ({})
    BOX_ALLOWLIST_PROJECT  dedicated project allowlist ({})
    BOX_SHARED_DIR         shared per-source policy dir ({})
    BOX_INJECT_SECRETS     secrets.json ({})
    BOX_CA_CERT            CA certificate PEM ({})
    BOX_CA_KEY             CA private key PEM ({})
    BOX_ACCESS_LOG         access log path ({})
    RUST_LOG               tracing filter (box_proxy=info,warn)",
        box_proxy::config::DEFAULT_LISTEN_ADDR,
        box_proxy::config::DEFAULT_GLOBAL_ALLOWLIST,
        box_proxy::config::DEFAULT_PROJECT_ALLOWLIST,
        box_proxy::config::DEFAULT_SHARED_DIR,
        box_proxy::config::DEFAULT_SECRETS,
        box_proxy::config::DEFAULT_CA_CERT,
        box_proxy::config::DEFAULT_CA_KEY,
        box_proxy::config::DEFAULT_ACCESS_LOG,
    );
}
