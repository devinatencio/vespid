pub mod dns;
pub mod http;
pub mod icmp;
pub mod ssl;
pub mod tcp;

use super::executor::CheckExecutor;
use std::collections::HashMap;

pub fn get_executors() -> HashMap<&'static str, Box<dyn CheckExecutor>> {
    let mut executors: HashMap<&'static str, Box<dyn CheckExecutor>> = HashMap::new();

    let h = http::HttpExecutor;
    executors.insert(http::HttpExecutor.check_type(), Box::new(h));

    let i = icmp::IcmpExecutor;
    executors.insert(icmp::IcmpExecutor.check_type(), Box::new(i));

    let t = tcp::TcpExecutor;
    executors.insert(tcp::TcpExecutor.check_type(), Box::new(t));

    let d = dns::DnsExecutor;
    executors.insert(dns::DnsExecutor.check_type(), Box::new(d));

    let s = ssl::SslExecutor;
    executors.insert(ssl::SslExecutor.check_type(), Box::new(s));

    executors
}

pub fn get_executor_for(check_type: &str) -> Option<Box<dyn CheckExecutor>> {
    match check_type {
        "http" => Some(Box::new(http::HttpExecutor)),
        "icmp" => Some(Box::new(icmp::IcmpExecutor)),
        "tcp" => Some(Box::new(tcp::TcpExecutor)),
        "dns" => Some(Box::new(dns::DnsExecutor)),
        "ssl" => Some(Box::new(ssl::SslExecutor)),
        _ => None,
    }
}
