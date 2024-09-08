use std::{fs, net::IpAddr, str::FromStr};

use quick_xml::{events::Event, Reader};

pub struct DmarcMessage {
    org_name: String,
    date_range_begin: u32,
    date_range_end: u32,
    header_from: String,
    source_ip: IpAddr,
    count: u32,
    dkim_result: bool,
    dkim_domain: String,
    spf_result: bool,
    spf_domain: String,
}

pub fn perse_dmarc_xml(xml_content: &str) -> Vec<DmarcMessage> {
    let mut reader = Reader::from_str(xml_content);
    reader.config_mut().trim_text(true);

    let mut _messages: Vec<DmarcMessage> = Vec::new();
    let mut _current_message = DmarcMessage {
        org_name: String::new(),
        date_range_begin: 0,
        date_range_end: 0,
        header_from: String::new(),
        source_ip: IpAddr::from_str("0.0.0.0").unwrap(),
        count: 0,
        dkim_result: false,
        dkim_domain: String::new(),
        spf_result: false,
        spf_domain: String::new(),
    };

    let mut _buf: Vec<DmarcMessage> = Vec::new();
    let mut _current_element = String::new();

    loop {
        match reader.read_event() {
            Ok(Event::Start(ref e)) => {
                _current_element = String::from_utf8(e.name().as_ref().to_vec()).unwrap();
            }
            Ok(Event::Text(e)) => {
                let text = e.unescape().unwrap();
                match _current_element.as_str() {
                    "org_name" => _current_message.org_name = text.to_string(),
                    "begin" => _current_message.date_range_begin = text.parse().unwrap(),
                    "end" => _current_message.date_range_end = text.parse().unwrap(),
                    "header_from" => _current_message.header_from = text.to_string(),
                    "source_ip" => _current_message.source_ip = IpAddr::from_str(&text).unwrap(),
                    "count" => _current_message.count = text.parse().unwrap(),
                    "dkim_result" => _current_message.dkim_result = text == "pass",
                    "dkim_domain" => _current_message.dkim_domain = text.to_string(),
                    "spf_result" => _current_message.spf_result = text == "pass",
                    "spf_message" => _current_message.spf_domain = text.to_string(),
                    _ => (),
                }
            }
            Ok(Event::End(ref e)) => {
                if String::from_utf8(e.name().as_ref().to_vec()).unwrap() == "record" {
                    _messages.push(_current_message);
                    _current_message = DmarcMessage {
                        org_name: String::new(),
                        date_range_begin: 0,
                        date_range_end: 0,
                        header_from: String::new(),
                        source_ip: IpAddr::from_str("0.0.0.0").unwrap(),
                        count: 0,
                        dkim_result: false,
                        dkim_domain: String::new(),
                        spf_result: false,
                        spf_domain: String::new(),
                    };
                }
            }
            Ok(Event::Eof) => break,
            Err(e) => panic!("Error at position {}: {:?}", reader.buffer_position(), e),
            _ => (),
        }
        _buf.clear();
    }
    _messages
}

fn main() {
    let xml_content = fs::read_to_string("dmarc.xml").unwrap();

    let messages = perse_dmarc_xml(&xml_content);
    for (i, message) in messages.iter().enumerate() {
        println!("Message {}", i + 1);
        println!("Organization: {}", message.org_name);
        println!(
            "Date Range: {} to {}",
            message.date_range_begin, message.date_range_end
        );
        println!("Header From: {}", message.header_from);
        println!("Source IP: {}", message.source_ip);
        println!("Count: {}", message.count);
        println!(
            "DKIM Result: {}",
            if message.dkim_result { "Pass" } else { "Fail" }
        );
        println!("DKIM Domain: {}", message.dkim_domain);
        println!(
            "SPF Result: {}",
            if message.spf_result { "Pass" } else { "Fail" }
        );
        println!();
    }
}
