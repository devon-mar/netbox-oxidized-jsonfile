use std::process::Command;

// https://www.keiruaprod.fr/blog/2020/05/12/include-version-in-rust-binary.html
fn main() {
    // taken from https://stackoverflow.com/questions/43753491/include-git-commit-hash-as-string-into-rust-program
    let output = Command::new("git")
        .args(["describe", "--dirty", "--always"])
        .output()
        .unwrap();
    let git_hash = String::from_utf8(output.stdout).unwrap();
    println!(
        "cargo:rustc-env=VERSION_STRING={}+{}",
        env!("CARGO_PKG_VERSION"),
        git_hash
    );
}
