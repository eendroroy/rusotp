use rusotp::{Algorithm, Radix, Secret, TOTP};
use std::io::{stdin, stdout, Stdout, Write};
use std::num::{NonZeroU64, NonZeroU8};
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use termion::event::Key;
use termion::input::TermRead;
use termion::raw::{IntoRawMode, RawTerminal};

fn main() {
    let stdin = stdin();
    let stdout = &mut stdout().into_raw_mode().unwrap();

    let secret = Secret::new("12345678901234567890").unwrap();
    let mut counter = 0;
    let mut length = NonZeroU8::new(6).unwrap();
    let mut radix = Radix::new(6).unwrap();
    let mut interval = NonZeroU64::new(5).unwrap();
    let mut totp = TOTP::new(Algorithm::SHA1, secret.clone(), length, radix, interval);
    let mut now: u64;
    let otp_now = &mut totp.generate().unwrap();
    let otp_at = &mut totp.generate_at(counter).unwrap();
    let step = 100;

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
                Key::Char('q') => break,
                Key::Char('i') => {
                    if interval.get() <= u64::MAX {
                        interval = NonZeroU64::new(interval.get() + 1).unwrap();
                        totp = TOTP::new(Algorithm::SHA1, secret.clone(), length, radix, interval);
                    }
                }
                Key::Char('j') => {
                    if interval.get() >= u64::MIN {
                        interval = NonZeroU64::new(interval.get() - 1).unwrap();
                        totp = TOTP::new(Algorithm::SHA1, secret.clone(), length, radix, interval);
                    }
                }
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
                        totp = TOTP::new(Algorithm::SHA1, secret.clone(), length, radix, interval);
                    }
                }
                Key::Left => {
                    let next_radix = Radix::new(radix.get() - 1);
                    if let Ok(r) = next_radix {
                        radix = r;
                        totp = TOTP::new(Algorithm::SHA1, secret.clone(), length, radix, interval);
                    }
                }
                Key::Up => {
                    if length.get() != u8::MAX {
                        let next_length = NonZeroU8::new(length.get() + 1);
                        if let Some(l) = next_length {
                            length = l;
                            totp = TOTP::new(Algorithm::SHA1, secret.clone(), length, radix, interval);
                        }
                    }
                }
                Key::Down => {
                    if length.get() != u8::MIN {
                        let next_length = NonZeroU8::new(length.get() - 1);
                        if let Some(l) = next_length {
                            length = l;
                            totp = TOTP::new(Algorithm::SHA1, secret.clone(), length, radix, interval);
                        }
                    }
                }
                _ => {}
            },
            Err(TryRecvError::Empty) => {}            // No key pressed
            Err(TryRecvError::Disconnected) => break, // Channel closed
        }

        now = std::time::UNIX_EPOCH.elapsed().unwrap().as_secs();
        *otp_now = totp.generate().unwrap();
        *otp_at = totp.generate_at(counter).unwrap();

        display(stdout, counter, interval.get(), length, radix, otp_at, now, otp_now);

        stdout.flush().unwrap();
        // Optionally, add a small sleep to reduce CPU usage
        thread::sleep(std::time::Duration::from_millis(100));
    }
}

fn display(
    stdout: &mut RawTerminal<Stdout>,
    counter: u64,
    interval: u64,
    length: NonZeroU8,
    radix: Radix,
    otp_at: &mut String,
    now: u64,
    otp_now: &mut String,
) -> () {
    write!(stdout, "'Ctrl-n' - Counter + 100 | 'Ctrl-p' - Counter - 100{}", termion::cursor::Goto(1, 2)).unwrap();
    write!(stdout, "'n' - Next Counter | 'p' - Previous Counter{}", termion::cursor::Goto(1, 3)).unwrap();
    write!(stdout, "'i' - Next Interval | 'j' - Previous Interval{}", termion::cursor::Goto(1, 4)).unwrap();
    write!(stdout, "'Right' - Increase Radix | 'Left' - Decrease Radix{}", termion::cursor::Goto(1, 5)).unwrap();
    write!(stdout, "'Up' - Increase Length | 'Down' - Decrease Length{}", termion::cursor::Goto(1, 6)).unwrap();
    write!(stdout, "`q` - Exit{}", termion::cursor::Goto(1, 9)).unwrap();
    write!(stdout, "Counter:  {}{}", counter, termion::cursor::Goto(1, 10)).unwrap();
    write!(stdout, "Interval: {}{}", interval, termion::cursor::Goto(1, 11)).unwrap();
    write!(stdout, "Length:   {}{}", length, termion::cursor::Goto(1, 12)).unwrap();
    write!(stdout, "Radix:    {}{}", radix.get(), termion::cursor::Goto(1, 14)).unwrap();
    write!(stdout, "OTP NOW:  {} @ ({}){}", otp_now, now, termion::cursor::Goto(1, 16)).unwrap();
    write!(stdout, "OTP AT:   {}{}", otp_at, termion::cursor::Goto(1, 17)).unwrap();
}
