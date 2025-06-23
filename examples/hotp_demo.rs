#[cfg(not(any(target_os = "windows")))]
use rusotp::{Algorithm, Radix, Secret, HOTP};
use std::io::{stdin, stdout, Stdout, Write};
use std::num::NonZeroU8;
use std::u64;
use termion::event::Key;
use termion::input::TermRead;
use termion::raw::{IntoRawMode, RawTerminal};

#[cfg(not(any(target_os = "windows")))]
fn main() {
    let stdin = stdin();
    let stdout = &mut stdout().into_raw_mode().unwrap();

    let secret = Secret::new("12345678901234567890").unwrap();
    let mut counter = 0;
    let mut length = NonZeroU8::new(6).unwrap();
    let mut radix = Radix::new(6).unwrap();
    let mut hotp = HOTP::new(Algorithm::SHA1, secret.clone(), length, radix);
    let otp = &mut hotp.generate(counter).unwrap();
    let step = 100;

    for c in stdin.keys() {
        write!(stdout, "{}{}", termion::cursor::Goto(1, 1), termion::clear::All).unwrap();

        match c.unwrap() {
            Key::Char('q') => break,
            Key::Ctrl('n') => {
                if counter <= u64::MAX - step {
                    counter += step;
                }
            }
            Key::Ctrl('p') => {
                if counter >= u64::MIN + step {
                    counter -= step;
                }
            }
            Key::Char('n') => {
                if counter != u64::MAX {
                    counter += 1;
                }
            }
            Key::Char('p') => {
                if counter != u64::MIN {
                    counter -= 1;
                }
            }
            Key::Right => {
                let next_radix = Radix::new(radix.get() + 1);
                if let Ok(r) = next_radix {
                    radix = r;
                    hotp = HOTP::new(Algorithm::SHA1, secret.clone(), length, radix);
                }
            }
            Key::Left => {
                let next_radix = Radix::new(radix.get() - 1);
                if let Ok(r) = next_radix {
                    radix = r;
                    hotp = HOTP::new(Algorithm::SHA1, secret.clone(), length, radix);
                }
            }
            Key::Up => {
                if length.get() != u8::MAX {
                    let next_length = NonZeroU8::new(length.get() + 1);
                    if let Some(l) = next_length {
                        length = l;
                        hotp = HOTP::new(Algorithm::SHA1, secret.clone(), l, radix);
                    }
                }
            }
            Key::Down => {
                if length.get() != u8::MIN {
                    let next_length = NonZeroU8::new(length.get() - 1);
                    if let Some(l) = next_length {
                        length = l;
                        hotp = HOTP::new(Algorithm::SHA1, secret.clone(), l, radix);
                    }
                }
            }
            _ => {}
        }

        *otp = hotp.generate(counter).unwrap();

        display(stdout, counter, length, radix, otp);

        stdout.flush().unwrap();
    }
}

fn display(stdout: &mut RawTerminal<Stdout>, counter: u64, length: NonZeroU8, radix: Radix, otp: &mut String) -> () {
    write!(stdout, "'Ctrl-n' - Next 100th Counter | 'Ctrl-p' - Previous 100th Counter{}", termion::cursor::Goto(1, 2))
        .unwrap();
    write!(stdout, "'n' - Next Counter | 'p' - Previous Counter{}", termion::cursor::Goto(1, 3)).unwrap();
    write!(stdout, "'Right' - Increase Radix | 'Left' - Decrease Radix{}", termion::cursor::Goto(1, 4)).unwrap();
    write!(stdout, "'Up' - Increase Length | 'Down' - Decrease Length{}", termion::cursor::Goto(1, 5)).unwrap();
    write!(stdout, "`q` - Exit{}", termion::cursor::Goto(1, 8)).unwrap();
    write!(stdout, "Counter: {}{}", counter, termion::cursor::Goto(1, 9)).unwrap();
    write!(stdout, "Length:  {}{}", length, termion::cursor::Goto(1, 10)).unwrap();
    write!(stdout, "Radix:   {}{}", radix.get(), termion::cursor::Goto(1, 12)).unwrap();
    write!(stdout, "OTP:     {}{}", otp, termion::cursor::Goto(1, 14)).unwrap();
}
