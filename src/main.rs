use std::env;
use std::process::{Command, Stdio};
use std::path::PathBuf;
use hypr_nav_lib::*;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: hypr-nav <h|j|k|l|left|right|up|down>");
        std::process::exit(1);
    }

    let (move_dir, kitty_dir) = match args[1].as_str() {
        "h" | "left" => ("l", "left"),
        "l" | "right" | "r" => ("r", "right"),
        "k" | "up" | "u" => ("u", "top"),
        "j" | "down" | "d" => ("d", "bottom"),
        _ => std::process::exit(2),
    };

    let hypr_socket = match find_hyprland_socket() {
        Some(path) => path,
        None => std::process::exit(1),
    };

    // Check if active window is Kitty
    if is_kitty_active(&hypr_socket) {
         let xdg = env::var("XDG_RUNTIME_DIR").unwrap_or_else(|_| "/tmp".to_string());
         let kitty_sock = PathBuf::from(&xdg).join("kitty");
         
         if kitty_sock.exists() {
             let status = Command::new("kitty")
                 .args(&[
                     "@",
                     "--to",
                     &format!("unix:{}", kitty_sock.display()),
                     "focus-window",
                     "--match",
                     &format!("neighbor:{}", kitty_dir),
                 ])
                 .stdout(Stdio::null())
                 .stderr(Stdio::null())
                 .status();

             if let Ok(s) = status {
                 if s.success() {
                     return;
                 }
             }
         }
    }

    hypr_dispatch(&hypr_socket, &format!("movefocus {}", move_dir));
}

fn is_kitty_active(socket_path: &PathBuf) -> bool {
    use std::io::Read;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    if let Ok(mut stream) = UnixStream::connect(socket_path) {
        if stream.write_all(b"activewindow").is_ok() {
            let mut response = String::new();
            if stream.read_to_string(&mut response).is_ok() {
                return response.contains("class: kitty");
            }
        }
    }
    false
}
