use serde::Serialize;

#[derive(Debug, PartialEq, Serialize)]
pub enum SSDP {
    Discover(Option<String>),
    Notify(String),
    BTSearch(String),
}
