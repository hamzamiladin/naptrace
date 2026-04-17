use colored::Colorize;
use std::io::Write;
use std::time::Duration;

// Generated with: figlet -f slant "naptrace"
const LOGO_LINES: [&str; 6] = [
    r"                      __                     ",
    r"   ____  ____ _____  / /__________ _________ ",
    r"  / __ \/ __ `/ __ \/ __/ ___/ __ `/ ___/ _ \",
    r" / / / / /_/ / /_/ / /_/ /  / /_/ / /__/  __/",
    r"/_/ /_/\__,_/ .___/\__/_/   \__,_/\___/\___/ ",
    r"           /_/                                ",
];

const TRACE_ICON: &str = "  -->--+-->  the twin hunter for CVEs";

/// Run the animated startup sequence.
/// A scanning trace line sweeps, then the logo types in, then the icon appears.
pub fn animate() {
    let mut stdout = std::io::stdout();

    println!();

    // Phase 1: Trace line sweeps across (like a scan)
    print!("  ");
    let trace_chars = ['>', '-', '-', '>', '-', '-', '>', '-', '-', '>'];
    for i in 0..48 {
        let ch = trace_chars[i % trace_chars.len()];
        let colored = if ch == '>' {
            format!("{ch}").bright_red()
        } else {
            format!("{ch}").red()
        };
        print!("{colored}");
        let _ = stdout.flush();
        std::thread::sleep(Duration::from_millis(6));
    }
    println!();
    std::thread::sleep(Duration::from_millis(60));

    // Phase 2: Logo types in line by line
    for line in &LOGO_LINES {
        for (j, ch) in line.chars().enumerate() {
            let colored = if ch == '/' || ch == '\\' || ch == '_' {
                format!("{ch}").red()
            } else {
                format!("{ch}").bright_red()
            };
            print!("{colored}");

            // Speed up as we go — first line slow, last line fast
            if j % 3 == 0 {
                let _ = stdout.flush();
                std::thread::sleep(Duration::from_millis(2));
            }
        }
        println!();
    }

    std::thread::sleep(Duration::from_millis(80));

    // Phase 3: Trace icon + tagline types in
    for (i, ch) in TRACE_ICON.chars().enumerate() {
        let colored = if i < 12 {
            // The -->--+--> part
            if ch == '>' || ch == '+' {
                format!("{ch}").bright_red()
            } else {
                format!("{ch}").red()
            }
        } else {
            format!("{ch}").bright_black()
        };
        print!("{colored}");
        let _ = stdout.flush();
        std::thread::sleep(Duration::from_millis(10));
    }
    println!();

    // Phase 4: Bottom trace
    print!("  ");
    for _ in 0..48 {
        print!("{}", "-".bright_black());
        let _ = stdout.flush();
        std::thread::sleep(Duration::from_millis(4));
    }
    println!("\n");
}

/// Print the banner without animation (for piped output or --quiet).
#[allow(dead_code)]
pub fn print_static() {
    println!();
    for line in &LOGO_LINES {
        println!("{}", line.red());
    }
    println!("{}", TRACE_ICON.bright_black());
    println!();
}
