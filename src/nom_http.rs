#![cfg_attr(rustfmt, rustfmt_skip)]
// NOTE: vendored from here until this is uploaded to crates.io:
// https://github.com/Geal/nom_benchmarks/blob/master/http/nom-http/src/main.rs
// All credits belong to @Geal

// #[macro_use]
// extern crate nom;

use nom::IResult;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while1};
use nom::character::complete::char;
use nom::multi::many1;
use nom::sequence::{delimited, pair, preceded, terminated};
// use std::env;
// use std::fs::File;

#[derive(Debug, PartialEq, Clone, Copy)]
pub struct Request<'a> {
    pub method:  &'a [u8],
    pub uri:     &'a [u8],
    pub version: &'a [u8],
}

#[derive(Debug, PartialEq)]
pub struct Header<'a> {
    pub name:  &'a [u8],
    pub value: Vec<&'a [u8]>,
}

fn is_token(c: u8) -> bool {
    !matches!(c,
        128..=255 |
        0..=31 |
        b'(' |
        b')' |
        b'<' |
        b'>' |
        b'@' |
        b',' |
        b';' |
        b':' |
        b'\\' |
        b'"' |
        b'/' |
        b'[' |
        b']' |
        b'?' |
        b'=' |
        b'{' |
        b'}' |
        b' '
    )
}

fn not_line_ending(c: u8) -> bool {
    c != b'\r' && c != b'\n'
}

fn is_space(c: u8) -> bool {
    c == b' '
}

fn is_not_space(c: u8)        -> bool { c != b' ' }
fn is_horizontal_space(c: u8) -> bool { c == b' ' || c == b'\t' }

fn is_version(c: u8) -> bool {
    (b'0'..=b'9').contains(&c) || c == b'.'
}

fn line_ending(input: &[u8]) -> IResult<&[u8], &[u8]> {
    alt((tag(b"\r\n"), tag(b"\n")))(input)
}

fn request_line(input: &[u8]) -> IResult<&[u8], Request> {
    let (input, method) = take_while1(is_token)(input)?;
    let (input, _) = take_while1(is_space)(input)?;
    let (input, uri) = take_while1(is_not_space)(input)?;
    let (input, _) = take_while1(is_space)(input)?;
    let (input, version) = http_version(input)?;
    let (input, _) = line_ending(input)?;

    Ok((input, Request {
        method,
        uri,
        version,
    }))
}

fn http_version(input: &[u8]) -> IResult<&[u8], &[u8]> {
    preceded(
        tag(b"HTTP/"),
        take_while1(is_version)
    )(input)
}

fn message_header_value(input: &[u8]) -> IResult<&[u8], &[u8]> {
    delimited(
        take_while1(is_horizontal_space),
        take_while1(not_line_ending),
        line_ending
    )(input)
}

fn message_header(input: &[u8]) -> IResult<&[u8], Header> {
    let (input, name) = take_while1(is_token)(input)?;
    let (input, _) = char(':')(input)?;
    let (input, value) = many1(message_header_value)(input)?;

    Ok((input, Header {
        name,
        value,
    }))
}

pub fn request(input: &[u8]) -> IResult<&[u8], (Request, Vec<Header>)> {
    terminated(
        pair(request_line, many1(message_header)),
        line_ending
    )(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn asdf() {
        let (_, (req, headers)) = request(b"GET / HTTP/1.1
Host: example.com
User-Agent: just/testing

").unwrap();

        assert_eq!(req, Request {
            method: b"GET",
            uri: b"/",
            version: b"1.1",
        });
        assert_eq!(headers, &[
            Header {
                name: b"Host",
                value: vec![b"example.com"],
            },
            Header {
                name: b"User-Agent",
                value: vec![b"just/testing"],
            },
        ]);
    }
}
