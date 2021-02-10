use chrono::prelude::{TimeZone, Utc};
use std::borrow::Cow;
use usiem::events::dns::{DnsEvent, DnsEventType, DnsRecordType};
use usiem::events::field::{SiemIp};
use usiem::events::{SiemEvent, SiemLog};

pub fn parse_log(log: SiemLog) -> Result<SiemLog, SiemLog> {
    let log_line = log.message();
    let (part1, _flags, part2) = match log_line.find("[") {
        Some(pos) => {
            let part1 = &log_line[..pos];
            let pos2 = match &log_line[pos..].find("]") {
                Some(pos) => *pos,
                None => return Err(log),
            };
            let flags = &log_line[pos + 1..pos + pos2];
            let part2 = &log_line[pos + pos2 + 1..];
            (part1, flags, part2)
        }
        None => return Err(log),
    };

    let am_pos = match get_date_message(part1) {
        Some(pos) => pos,
        None => return Err(log),
    };
    let event_created = match Utc.datetime_from_str(&part1[..am_pos], "%d/%m/%Y %H:%M:%S %P") {
        Ok(timestamp) => timestamp.timestamp_millis(),
        Err(_err) => return Err(log),
    };
    let part1_fields = extract_fields(part1);
    let part2_fields = extract_fields(part2);

    let mut log = SiemLog::new(
        log.message().to_string(),
        log.event_received(),
        log.origin().clone(),
    );
    log.set_event_created(event_created);
    log.set_vendor(Cow::Borrowed("Microsoft"));
    log.set_product(Cow::Borrowed("DNS Server"));
    log.set_category(Cow::Borrowed("DNS"));
    log.set_service(Cow::Borrowed("DNS"));

    let source_ip = match part1_fields.get(8) {
        Some(ip) => match SiemIp::from_ip_str(ip.to_string()) {
            Ok(ip) => ip,
            Err(_) => return Err(log),
        },
        None => return Err(log),
    };
    let destination_ip = log.origin().clone();
    let op_code = match part1_fields.get(7) {
        Some(operation) => match operation {
            &"Snd" => DnsEventType::ANSWER,
            &"Rcv" => DnsEventType::QUERY,
            _ => return Err(log),
        },
        None => return Err(log),
    };

    let record_name = match part2_fields.get(1) {
        Some(rcr) => parse_record_name(rcr),
        None => return Err(log),
    };
    let record_type = match part2_fields.get(0) {
        Some(rcr) => match rcr {
            &"A" => DnsRecordType::A,
            &"AAAA" => DnsRecordType::AAAA,
            &"CERT" => DnsRecordType::CERT,
            &"CNAME" => DnsRecordType::CNAME,
            &"MX" => DnsRecordType::MX,
            &"NS" => DnsRecordType::NS,
            &"PTR" => DnsRecordType::PTR,
            &"SOA" => DnsRecordType::SOA,
            &"SRV" => DnsRecordType::SRV,
            &"TXT" => DnsRecordType::TXT,
            _ => return Err(log),
        },
        None => return Err(log),
    };

    let dns_event = DnsEvent {
        source_ip,
        destination_ip,
        op_code,
        record_name: Cow::Owned(record_name),
        record_type,
        data: None,
    };
    log.set_event(SiemEvent::DNS(dns_event));
    Ok(log)
}

pub fn get_date_message<'a>(message: &'a str) -> Option<usize> {
    let mut whitespaces = 0;
    let mut last_whitespace = 0;
    for (i, c) in message.char_indices() {
        if c == ' ' {
            if whitespaces == 2 {
                if &message[last_whitespace..i] == "AM" || &message[last_whitespace..i] == "PM" {
                    return Some(i);
                } else {
                    return None;
                }
            } else {
                last_whitespace = i + 1;
            }
            whitespaces += 1;
        }
    }
    None
}

pub fn parse_record_name(record: &str) -> String {
    let mut is_counter = false;
    let mut ret = String::with_capacity(record.len());
    let mut to_check = String::from("0");
    for (_i, c) in record.char_indices() {
        if c == '(' {
            is_counter = true;
        } else if c == ')' {
            is_counter = false;
            if to_check != "0" && ret.len() > 0 {
                ret.push('.');
                to_check = String::new();
            }
            
        } else if !is_counter {
            ret.push(c);
        }else{
            to_check.push(c);
        }
    }
    return ret;
}

pub fn extract_fields<'a>(message: &'a str) -> Vec<&'a str> {
    let mut field_map = Vec::with_capacity(20);
    let mut start_field = 0;
    let mut last_char = ' ';
    for (i, c) in message.char_indices() {
        if c == ' ' {
            if last_char == ' ' {
                start_field = i + 1;
            } else {
                field_map.push(&message[start_field..i]);
                start_field = i + 1;
            }
        }
        last_char = c;
    }
    field_map.push(&message[start_field..]);
    field_map
}

#[cfg(test)]
mod filterlog_tests {
    use super::{extract_fields, parse_log};
    use std::borrow::Cow;
    use usiem::events::field::{SiemField, SiemIp};
    use usiem::events::SiemLog;

    #[test]
    fn test_extract_fields() {
        let log = "6/5/2013 10:00:32 AM 0E70 PACKET  00000000033397A0 UDP Rcv 10.161.60.71    5b47   Q [0001   D   NOERROR] A      (12)somecomputer(6)domain(3)com(0)";
        let map = extract_fields(log);
        assert_eq!(map.get(0), Some(&"6/5/2013"));
        assert_eq!(map.get(1), Some(&"10:00:32"));
        assert_eq!(map.get(2), Some(&"AM"));
        assert_eq!(map.get(6), Some(&"UDP"));
    }

    #[test]
    fn test_parse_dns() {
        let log = "6/5/2013 10:00:32 AM 0E70 PACKET  00000000033397A0 UDP Rcv 10.161.60.71    5b47   Q [0001   D   NOERROR] A      (12)somecomputer(6)domain(3)com(0)";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let siem_log = parse_log(log);
        match siem_log {
            Ok(log) => {
                assert_eq!(log.service(), "DNS");
                assert_eq!(
                    log.field("source.ip"),
                    Some(&SiemField::IP(
                        SiemIp::from_ip_str(Cow::Borrowed("10.161.60.71")).unwrap()
                    ))
                );
                assert_eq!(
                    log.field("destination.ip"),
                    Some(&SiemField::IP(
                        SiemIp::from_ip_str(Cow::Borrowed("0.0.0.0")).unwrap()
                    ))
                );
                assert_eq!(
                    log.field("dns.question.name"),
                    Some(&SiemField::from_str(Cow::Borrowed(
                        "somecomputer.domain.com"
                    )))
                );
            }
            Err(_) => assert_eq!(1, 0),
        }
    }
}
