//! Start-up banner.
//!
//! The art is painted one cell at a time with a true-colour gradient that runs
//! from light blue at the top left to deep blue at the bottom right, so the
//! colour of every character is a function of its position rather than a
//! single flat foreground applied to the whole block.

use std::io::{self, IsTerminal, Write};

use crossterm::style::{Color, ResetColor, SetForegroundColor};
use crossterm::QueueableCommand;

/// The ASCII art shown on start-up.
const ART: &str = r#"
                                                 _.oo.
                         _.u[[/;:,.         .odMMMMMM'
                      .o888UU[[[/;:-.      .o@P^    MMM^
                     oN88888UU[[[/;::-.        dP^
                    dNMMNN888UU[[[/;:--.   .o@P^
                   MMMMMMMN888UU[[/;::-. o@^
                   NNMMMNN888UU[[[/~.o@P^
                   888888888UU[[[/o@^-..
                  oI8888UU[[[/o@P^:--..
             .@^   YUU[[[/o@^;::---..
           oMP     ^/o@P^;:::---..
        .dMMM    .o@^ ^;::---...
       dMMMMMMM@^`       `^^^^
      YMMMUP^
        ^^
"#;

/// Light end of the gradient.
const LIGHT: (u8, u8, u8) = (150, 214, 255);
/// Dark end of the gradient.
const DARK: (u8, u8, u8) = (10, 32, 96);

/// Linear interpolation between the two ends of the gradient.
fn blend(t: f32) -> Color {
    let t = t.clamp(0.0, 1.0);
    let channel = |from: u8, to: u8| (from as f32 + (to as f32 - from as f32) * t).round() as u8;
    Color::Rgb {
        r: channel(LIGHT.0, DARK.0),
        g: channel(LIGHT.1, DARK.1),
        b: channel(LIGHT.2, DARK.2),
    }
}

/// Print the banner, followed by the tagline and the scope notice.
pub fn show(tagline: &str, scope: &str) {
    let lines: Vec<&str> = ART.lines().skip(1).collect();
    let rows = lines.len().max(1) as f32;
    let columns = lines
        .iter()
        .map(|line| line.chars().count())
        .max()
        .unwrap_or(1)
        .max(1) as f32;

    let mut stdout = io::stdout();
    let coloured = stdout.is_terminal();

    println!();
    for (row, line) in lines.iter().enumerate() {
        if !coloured {
            println!("{line}");
            continue;
        }
        for (column, character) in line.chars().enumerate() {
            if character == ' ' {
                print!(" ");
                continue;
            }
            // Blending both axes keeps the gradient diagonal, so the shape
            // reads as lit from the top left rather than banded.
            let t = 0.5 * (row as f32 / rows) + 0.5 * (column as f32 / columns);
            let _ = stdout.queue(SetForegroundColor(blend(t)));
            let _ = write!(stdout, "{character}");
        }
        let _ = stdout.queue(ResetColor);
        let _ = writeln!(stdout);
    }
    let _ = stdout.flush();

    println!();
    let title = "s y s t e m - a d m i n i s t r a t i o n";
    let indent = " ".repeat(((columns as usize).saturating_sub(title.chars().count())) / 2);
    if coloured {
        let _ = stdout.queue(SetForegroundColor(blend(0.35)));
        let _ = writeln!(stdout, "{indent}{title}");
        let _ = stdout.queue(ResetColor);
        let _ = stdout.flush();
    } else {
        println!("{indent}{title}");
    }
    println!();
    println!("  {tagline}");
    println!("  {scope}");
    println!();
}
