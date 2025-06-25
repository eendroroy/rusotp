use colored::Color::{BrightBlue, BrightCyan, Green, Red, Yellow};
use colored::Colorize;
use rusotp::HOTP;
#[cfg(not(any(target_os = "windows")))]
use rusotp::{Algorithm, Radix, Secret, TOTP};
use std::io::{stdin, stdout, Stdout, Write};
use std::num::{NonZeroU64, NonZeroU8};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use termion::event::Key;
use termion::input::TermRead;
use termion::raw::{IntoRawMode, RawTerminal};

#[cfg(not(any(target_os = "windows")))]
fn main() {
    let stdin = stdin();
    let stdout = &mut stdout().into_raw_mode().unwrap();

    let secret = Secret::new("asdlkjfaghkjfgahlsdfku%aweyr8q937yregl7aiwgkfd&*%^*&SUAkJHGLKDFJSGHFHK3o84q7gd").unwrap();
    let mut counter = 0;
    let mut length = NonZeroU8::new(6).unwrap();
    let mut radix = Radix::new(10).unwrap();
    let mut interval = NonZeroU64::new(5).unwrap();
    let mut totp = TOTP::new(Algorithm::SHA1, secret.clone(), length, radix, interval);
    let mut hotp = HOTP::new(Algorithm::SHA1, secret.clone(), length, radix);
    let mut now: u64;
    let mut next: u64;
    let t_otp_now = &mut totp.generate().unwrap();
    let t_otp_at = &mut totp.generate_at(counter).unwrap();
    let h_otp = &mut hotp.generate(counter).unwrap();

    // Channel for key events
    let (tx, rx) = mpsc::channel();

    // Spawn thread for key reading
    thread::spawn(move || {
        for key in stdin.lock().keys() {
            if let Ok(k) = key {
                if tx.send(k).is_err() {
                    break;
                }
            }
        }
    });

    loop {
        write!(stdout, "{}{}", termion::cursor::Goto(1, 1), termion::clear::All).unwrap();

        // Non-blocking receive
        match rx.try_recv() {
            Ok(c) => match c {
                Key::Char('q') | Key::Ctrl('c') => break,
                Key::Char('i') => {
                    if interval.get() <= u64::MAX {
                        interval = NonZeroU64::new(interval.get() + 1).unwrap();
                    }
                }
                Key::Char('I') => {
                    if interval.get() >= u64::MIN {
                        interval = NonZeroU64::new(interval.get() - 1).unwrap();
                    }
                }
                Key::Char('n') => counter = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs(),
                Key::Char('N') => counter = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs() / interval.get(),
                Key::Char('c') => {
                    if counter != u64::MAX {
                        counter += 1;
                    }
                }
                Key::Char('C') => {
                    if counter != u64::MIN {
                        counter -= 1;
                    }
                }
                Key::Char('d') => {
                    if counter + 10 <= u64::MAX {
                        counter += 10;
                    }
                }
                Key::Char('D') => {
                    if counter >= u64::MIN + 10 {
                        counter -= 10;
                    }
                }
                Key::Char('e') => {
                    if counter <= u64::MAX / 10 {
                        counter *= 10;
                    }
                }
                Key::Char('E') => {
                    if counter >= u64::MIN / 10 {
                        counter /= 10;
                    }
                }
                Key::Char('f') => {
                    if counter <= u64::MAX / 50 {
                        counter *= 50;
                    }
                }
                Key::Char('F') => {
                    if counter >= u64::MIN / 50 {
                        counter /= 50;
                    }
                }
                Key::Char('r') => {
                    let next_radix = Radix::new(radix.get() + 1);
                    if let Ok(r) = next_radix {
                        radix = r;
                    }
                }
                Key::Char('R') => {
                    let next_radix = Radix::new(radix.get() - 1);
                    if let Ok(r) = next_radix {
                        radix = r;
                    }
                }
                Key::Char('l') => {
                    if length.get() != u8::MAX {
                        let next_length = NonZeroU8::new(length.get() + 1);
                        if let Some(l) = next_length {
                            length = l;
                        }
                    }
                }
                Key::Char('L') => {
                    if length.get() != u8::MIN {
                        let next_length = NonZeroU8::new(length.get() - 1);
                        if let Some(l) = next_length {
                            length = l;
                        }
                    }
                }
                _ => {}
            },
            Err(TryRecvError::Empty) => {}            // No key pressed
            Err(TryRecvError::Disconnected) => break, // Channel closed
        }

        totp = TOTP::new(Algorithm::SHA1, secret.clone(), length, radix, interval);
        hotp = HOTP::new(Algorithm::SHA1, secret.clone(), length, radix);

        now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
        next = now - (now % interval.get()) + interval.get();

        *t_otp_now = totp.generate().unwrap();
        *t_otp_at = totp.generate_at(counter).unwrap();
        *h_otp = hotp.generate(counter).unwrap();

        display(stdout, counter, interval.get(), length, radix, t_otp_at, now, next, t_otp_now, h_otp);

        stdout.flush().unwrap();

        thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn display(
    stdout: &mut RawTerminal<Stdout>,
    counter: u64,
    interval: u64,
    length: NonZeroU8,
    radix: Radix,
    t_otp_at: &mut String,
    now: u64,
    next: u64,
    t_otp_now: &mut String,
    h_otp: &mut String,
) -> () {
    let mut line: u16 = 1;

    let mut next_line = |step: u16| -> termion::cursor::Goto {
        line += step;
        termion::cursor::Goto(1, line)
    };

    [
        (
            "'n' -- Counter = NOW() | 'Shift-n' -- Counter = NOW() / interval "
                .bold()
                .color(Green),
            next_line(1),
        ),
        ("'c' -- Counter + 1     | 'Shift-c' -- Counter - 1".bold().color(Green), next_line(1)),
        ("'d' -- Counter + 10    | 'Shift-d' -- Counter - 10".bold().color(Green), next_line(1)),
        ("'e' -- Counter * 10    | 'Shift-e' -- Counter / 10".bold().color(Green), next_line(1)),
        ("'f' -- Counter * 50    | 'Shift-f' -- Counter / 50".bold().color(Green), next_line(1)),
        ("'i' -- Interval + 1    | 'Shift-i' -- Interval - 1".bold().color(Green), next_line(1)),
        ("'r' -- Radix + 1       | 'Shift-r' -- Radix - 1".bold().color(Green), next_line(1)),
        ("'l' -- Length + 1      | 'Shift-l' -- Length - 1".bold().color(Green), next_line(1)),
        ("`q`, `Ctrl-c` - Exit".bold().color(Red), next_line(2)),
    ]
    .iter()
    .for_each(|(text, row)| {
        write!(stdout, "{}{}", text, row).unwrap();
    });

    write!(
        stdout,
        "{}{}",
        format!("Counter: {} | Interval: {} | Length: {} | Radix: {}", counter, interval, length.get(), radix.get())
            .bold()
            .color(BrightCyan),
        next_line(2)
    )
    .unwrap();
    write!(stdout, "{}  {}", "TOTP --->".color(BrightBlue), next_line(1)).unwrap();
    write!(
        stdout,
        "{}  {} @  ({}) [{}]{}",
        "     NOW:".color(BrightBlue),
        t_otp_now.bold().color(Yellow),
        now,
        next - now,
        next_line(1)
    )
    .unwrap();
    write!(stdout, "           {: >width$} @> ({}){}", "", next, next_line(1), width = t_otp_now.len()).unwrap();
    write!(stdout, "{}  {}{}", "      AT:".color(BrightBlue), t_otp_at.bold().color(Yellow), next_line(1)).unwrap();
    write!(stdout, "{}  {}", "HOTP --->".color(BrightBlue), next_line(1)).unwrap();
    write!(stdout, "{}  {}{}", "      AT:".color(BrightBlue), h_otp.bold().color(Yellow), next_line(1)).unwrap();
}
