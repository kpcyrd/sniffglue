#![cfg_attr(rustfmt, rustfmt_skip)]
// NOTE: vendored from here until this is uploaded to crates.io:
// https://github.com/Geal/nom_benchmarks/blob/master/http/nom-http/src/main.rs
// All credits belong to @Geal

// #[macro_use]
// extern crate nom;

use nom::IResult;
// use std::env;
// use std::fs::File;

#[derive(Debug)]
pub struct Request<'a> {
    pub method:  &'a [u8],
    pub uri:     &'a [u8],
    pub version: &'a [u8],
}

#[derive(Debug)]
pub struct Header<'a> {
    pub name:  &'a [u8],
    pub value: Vec<&'a [u8]>,
}

fn is_token(c: u8) -> bool {
    match c {
        128...255 => false,
        0...31    => false,
        b'('      => false,
        b')'      => false,
        b'<'      => false,
        b'>'      => false,
        b'@'      => false,
        b','      => false,
        b';'      => false,
        b':'      => false,
        b'\\'     => false,
        b'"'      => false,
        b'/'      => false,
        b'['      => false,
        b']'      => false,
        b'?'      => false,
        b'='      => false,
        b'{'      => false,
        b'}'      => false,
        b' '      => false,
        _         => true,
    }
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
    c >= b'0' && c <= b'9' || c == b'.'
}

named!(line_ending, alt!(tag!("\r\n") | tag!("\n")));

fn request_line<'a>(input: &'a [u8]) -> IResult<&'a[u8], Request<'a>> {
  do_parse!(input,
    method: take_while1!(is_token)     >>
            take_while1!(is_space)     >>
    url:    take_while1!(is_not_space) >>
            take_while1!(is_space)     >>
    version: http_version              >>
    line_ending                        >>
    ( Request {
        method: method,
        uri:    url,
        version: version,
    } )
  )
}

named!(http_version, preceded!(
    tag!("HTTP/"),
    take_while1!(is_version)
));

named!(message_header_value, delimited!(
    take_while1!(is_horizontal_space),
    take_while1!(not_line_ending),
    line_ending
));

fn message_header<'a>(input: &'a [u8]) -> IResult<&'a[u8], Header<'a>> {
  do_parse!(input,
    name:   take_while1!(is_token)       >>
            char!(':')                   >>
    values: many1!(message_header_value) >>

    ( Header {
        name: name,
        value: values,
    } )
  )
}

pub fn request<'a>(input: &'a [u8]) -> IResult<&'a[u8], (Request<'a>, Vec<Header<'a>>)> {
  terminated!(input,
    pair!(request_line, many1!(message_header)),
    line_ending
  )
}


/*
pub fn parse(data:&[u8]) -> Option<Vec<(Request, Vec<Header>)>> {
  let mut buf = &data[..];
  let mut v = Vec::new();
  loop {
    match request(buf) {
      IResult::Done(b, r) => {
        buf = b;
        v.push(r);

        if b.is_empty() {

    //println!("{}", i);
          break;
        }
      },
      IResult::Error(_e) => return None/*panic!("{:?}", e)*/,
      IResult::Incomplete(_) => return None/*panic!("Incomplete!")*/,
    }
  }

  Some(v)
}

fn main() {
    let mut contents: Vec<u8> = Vec::new();

    {
        use std::io::Read;

        let mut file = File::open(env::args().nth(1).expect("File to read")).ok().expect("Failed to open file");

        let _ = file.read_to_end(&mut contents).unwrap();
    }
    
    let mut buf = &contents[..];
    loop { parse(buf); }
}
*/
