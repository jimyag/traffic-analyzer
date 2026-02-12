use std::env;
use std::fs;
use std::path::{Path, PathBuf};

fn main() {
    println!("cargo:rustc-check-cfg=cfg(embedded_bpf)");
    println!("cargo:rerun-if-env-changed=TRAFFIC_ANALYZER_EMBED_BPF");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent().expect("workspace root").to_path_buf();
    let required = env_flag("TRAFFIC_ANALYZER_EMBED_BPF");

    let candidates = bpf_candidates(&workspace_root);
    for path in &candidates {
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let Some(source) = candidates.into_iter().find(|p| p.exists()) else {
        if required {
            panic!("TRAFFIC_ANALYZER_EMBED_BPF is enabled, but no eBPF object was found under target/bpfel-unknown-none");
        }
        return;
    };

    let out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR"));
    let out_path = out_dir.join("embedded-traffic-analyzer-ebpf.bin");
    if let Err(err) = copy_file(&source, &out_path) {
        panic!(
            "failed to copy eBPF object from {} to {}: {}",
            source.display(),
            out_path.display(),
            err
        );
    }

    println!("cargo:rustc-cfg=embedded_bpf");
    println!(
        "cargo:rustc-env=TRAFFIC_ANALYZER_EMBED_BPF_PATH={}",
        out_path.display()
    );
    println!(
        "cargo:warning=embedding eBPF object from {}",
        source.display()
    );
}

fn bpf_candidates(workspace_root: &Path) -> Vec<PathBuf> {
    let target_root = workspace_root.join("target").join("bpfel-unknown-none");
    vec![
        target_root
            .join("release")
            .join("libtraffic_analyzer_ebpf.so"),
        target_root.join("release").join("traffic-analyzer-ebpf"),
        target_root.join("release").join("traffic_analyzer_ebpf"),
        target_root
            .join("debug")
            .join("libtraffic_analyzer_ebpf.so"),
        target_root.join("debug").join("traffic-analyzer-ebpf"),
        target_root.join("debug").join("traffic_analyzer_ebpf"),
    ]
}

fn copy_file(source: &Path, target: &Path) -> std::io::Result<u64> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(source, target)
}

fn env_flag(key: &str) -> bool {
    match env::var(key) {
        Ok(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}
