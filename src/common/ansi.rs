#![allow(unused)]

use std::fmt::{self, Display};

use supports_color::Stream;
const BLACK: &str = "\x1b[0;30m";
const RED: &str = "\x1b[0;31m";
const GREEN: &str = "\x1b[0;32m";
const YELLOW: &str = "\x1b[0;33m";
const BLUE: &str = "\x1b[0;34m";
const PURPLE: &str = "\x1b[0;35m";
const CYAN: &str = "\x1b[0;36m";
const WHITE: &str = "\x1b[0;37m";
const GRAY: &str = "\x1b[38;5;248m";
const RESET: &str = "\x1b[0m";
const ITALIC: &str = "\x1b[3m";

pub fn red<T: Display>(content: T) -> Styled<T> {
    Styled {
        style: RED,
        content,
    }
}

pub fn green<T: Display>(content: T) -> Styled<T> {
    Styled {
        style: GREEN,
        content,
    }
}

pub fn yellow<T: Display>(content: T) -> Styled<T> {
    Styled {
        style: YELLOW,
        content,
    }
}

pub fn blue<T: Display>(content: T) -> Styled<T> {
    Styled {
        style: BLUE,
        content,
    }
}

pub fn gray<T: Display>(content: T) -> Styled<T> {
    Styled {
        style: GRAY,
        content,
    }
}

pub trait Print: Sized {
    fn print(&self, f: &mut fmt::Formatter<'_>, with_color: bool) -> fmt::Result;

    fn display<'a>(&'a self, with_color: bool) -> impl Display {
        struct Printable<'a, P: Print> {
            with_color: bool,
            content: &'a P,
        }

        impl<'a, P: Print> Display for Printable<'a, P> {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.content.print(f, self.with_color)
            }
        }

        Printable {
            with_color,
            content: self,
        }
    }
}

impl<T: Display> Print for T {
    fn print(&self, f: &mut fmt::Formatter<'_>, with_color: bool) -> fmt::Result {
        self.fmt(f)
    }
}

pub struct Styled<T: Display> {
    style: &'static str,
    content: T,
}

impl<T: Display> Print for Styled<T> {
    fn print(&self, f: &mut fmt::Formatter<'_>, with_color: bool) -> fmt::Result {
        if with_color {
            self.style.fmt(f)?;
        }

        self.content.fmt(f)?;

        if with_color {
            RESET.fmt(f)?;
        }

        Ok(())
    }
}

#[macro_export]
macro_rules! println {
    () => {
        std::println!()
    };
    ($s:literal) => {
        std::println!($s)
    };
    ($s:literal, $($arg:expr),*) => {
        #[allow(unused_variables)]
        let with_color = supports_color::on_cached(supports_color::Stream::Stdout)
            .map_or(false, |l| l.has_basic);
        std::println!($s, $(crate::common::ansi::Print::display(&$arg, with_color)),*)
    };
    ($s:literal, $($arg:expr),*,) => {
        #[allow(unused_variables)]
        let with_color = supports_color::on_cached(supports_color::Stream::Stdout)
            .map_or(false, |l| l.has_basic);
        std::println!($s, $(crate::common::ansi::Print::display(&$arg, with_color)),*)
    };
}

pub use println;

#[macro_export]
macro_rules! eprintln {
    () => {
        std::eprintln!()
    };
    ($s:literal) => {
        std::eprintln!($s)
    };
    ($s:literal, $($arg:expr),*) => {
        #[allow(unused_variables)]
        let with_color = supports_color::on_cached(supports_color::Stream::Stderr)
            .map_or(false, |l| l.has_basic);
        std::eprintln!($s, $(crate::common::ansi::Print::display(&$arg, with_color)),*)
    };
    ($s:literal, $($arg:expr),*,) => {
        #[allow(unused_variables)]
        let with_color = supports_color::on_cached(supports_color::Stream::Stderr)
            .map_or(false, |l| l.has_basic);
        std::eprintln!($s, $(crate::common::ansi::Print::display(&$arg, with_color)),*)
    };
}

pub use eprintln;
