use usiem::chrono::prelude::{TimeZone, Utc};
use std::borrow::Cow;
use usiem::components::common::LogParsingError;
use usiem::events::dns::{DnsEvent, DnsEventType, DnsRecordType};
use usiem::events::field::{SiemIp, SiemField};
use usiem::events::{SiemEvent, SiemLog};

pub fn parse_log(log: SiemLog) -> Result<SiemLog, LogParsingError> {
    let log_line = log.message();
    let (part1, _flags, part2) = match log_line.find("[") {
        Some(pos) => {
            let part1 = &log_line[..pos];
            let pos2 = match &log_line[pos..].find("]") {
                Some(pos) => *pos,
                None => return Err(LogParsingError::NoValidParser(log)),
            };
            let flags = &log_line[pos + 1..pos + pos2];
            let part2 = &log_line[pos + pos2 + 1..];
            (part1, flags, part2)
        }
        None => return Err(LogParsingError::NoValidParser(log)),
    };

    let (event_created, start_text_pos) = match extract_date(part1) {
        Some(pos) => pos,
        None => return Err(LogParsingError::NoValidParser(log)),
    };
    let part1 = &part1[start_text_pos..];

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

    let ip_host_log = match part1_fields.get(5) {
        Some(ip) => match SiemIp::from_ip_str(*ip) {
            Ok(ip) => ip,
            Err(_) => return Err(LogParsingError::ParserError(log)),
        },
        None => return Err(LogParsingError::ParserError(log)),
    };
    let ip_server = log.origin().clone();
    let send_recv = match part1_fields.get(4) {
        Some(operation) => match operation {
            &"Snd" => "Snd",
            &"Rcv" => "Rcv",
            _ => return Err(LogParsingError::ParserError(log)),
        },
        None => return Err(LogParsingError::ParserError(log)),
    };
    let transaction_id = match part1_fields.get(6) {
        Some(transaction) => *transaction,
        None => return Err(LogParsingError::ParserError(log)),
    };
    log.add_field("transaction.id", SiemField::from_str(transaction_id.to_string()));
    let (q_r, _op)= match part1_fields.get(7) {
        Some(q_r) => {
            if *q_r == "R" {
                // Response
                let op = match part1_fields.get(8){
                    Some(op) => op,
                    None => return Err(LogParsingError::ParserError(log))
                };
                ("R", *op)
            }else{
                // Query
                ("Q",*q_r)
            }
        }
        None => return Err(LogParsingError::ParserError(log)),
    };
    let (op_code, source_ip, destination_ip) = if send_recv == "Rcv" && q_r == "Q" {
        // Server receives a query from a host
        (DnsEventType::QUERY, ip_host_log, ip_server)
    }else if send_recv == "Snd" && q_r == "R" {
        // Host sends a query to this server
        (DnsEventType::ANSWER, ip_server, ip_host_log)
    }else if send_recv == "Snd" && q_r == "Q" {
        // Server sends a query to a external server
        (DnsEventType::QUERY, ip_server, ip_host_log)
    }else if send_recv == "Rcv" && q_r == "R" {
        // Server receives an answer from a external server
        (DnsEventType::ANSWER, ip_host_log, ip_server)
    }else{
        (DnsEventType::QUERY, ip_host_log, ip_server)
    };

    let record_name = match part2_fields.get(1) {
        Some(rcr) => parse_record_name(rcr),
        None => return Err(LogParsingError::ParserError(log)),
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
            _ => return Err(LogParsingError::ParserError(log)),
        },
        None => return Err(LogParsingError::ParserError(log)),
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
                    return Some(last_whitespace);
                }
            } else {
                last_whitespace = i + 1;
            }
            whitespaces += 1;
        }
    }
    None
}

pub fn extract_date(message: &str) -> Option<(i64, usize)> {
    let mut whitespaces = 0;
    let mut last_whitespace = 0;
    for (i, c) in message.char_indices() {
        if c == ' ' {
            if whitespaces == 2 {
                if &message[last_whitespace + 1..i] == "AM"
                    || &message[last_whitespace + 1..i] == "PM"
                {
                    match Utc.datetime_from_str(&message[..i], "%d/%m/%Y %H:%M:%S %P") {
                        Ok(timestamp) => return Some((timestamp.timestamp_millis(), i + 1)),
                        Err(_err) => return None,
                    };
                } else {
                    match Utc.datetime_from_str(&message[..last_whitespace], "%d/%m/%Y %H:%M:%S") {
                        Ok(timestamp) => {
                            return Some((timestamp.timestamp_millis(), last_whitespace + 1))
                        }
                        Err(_err) => return None,
                    };
                }
            } else {
                last_whitespace = i;
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
        } else {
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
    use usiem::events::dns::DnsEventType;
    use usiem::events::field::{SiemField, SiemIp};
    use usiem::events::{SiemLog, SiemEvent};

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
        let log = parse_log(log).expect("Must parse log");
        assert_eq!(log.service(), "DNS");
        assert_eq!(
            log.field("source.ip"),
            Some(&SiemField::IP(SiemIp::from_ip_str("10.161.60.71").unwrap()))
        );
        assert_eq!(
            log.field("destination.ip"),
            Some(&SiemField::IP(SiemIp::from_ip_str("0.0.0.0").unwrap()))
        );
        assert_eq!(
            log.field("dns.question.name"),
            Some(&SiemField::from_str(Cow::Borrowed(
                "somecomputer.domain.com"
            )))
        );
    }

    #[test]
    fn test_parse_dns_question_to_server() {
        // ["0E1C", "PACKET", "0000017DEDFE28D0", "UDP", "Rcv", "10.20.0.6", "966f", "Q", ""]
        let log = "22/12/2021 21:46:04 0E1C PACKET  0000017DEDFE28D0 UDP Rcv 10.20.0.6       966f   Q [0001   D   NOERROR] A      (5)login(4)live(3)com(0)";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(0));
        let log = parse_log(log).expect("Must parse the log");
        assert_eq!(log.service(), "DNS");
        assert_eq!(
            log.field("source.ip"),
            Some(&SiemField::IP(SiemIp::from_ip_str("10.20.0.6").unwrap()))
        );
        assert_eq!(
            log.field("destination.ip"),
            Some(&SiemField::IP(SiemIp::from_ip_str("0.0.0.0").unwrap()))
        );
        assert_eq!(
            log.field("dns.question.name"),
            Some(&SiemField::from_str(Cow::Borrowed("login.live.com")))
        );
    }

    #[test]
    fn test_parse_dns_question_to_external_server() {
        // ["0E1C", "PACKET", "0000017DEDFE28D0", "UDP", "Rcv", "10.20.0.6", "966f", "Q", ""]
        let log = "22/12/2021 21:46:04 0E1C PACKET  0000017DEDE1F920 UDP Snd 8.8.4.4         624d   Q [0001   D   NOERROR] A      (5)login(4)live(3)com(0)";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(3));
        let log = parse_log(log).expect("Must parse the log");
        assert_eq!(log.service(), "DNS");
        assert_eq!(
            log.field("source.ip"),
            Some(&SiemField::IP(SiemIp::V4(3)))
        );
        assert_eq!(
            log.field("destination.ip"),
            Some(&SiemField::IP(SiemIp::from_ip_str("8.8.4.4").unwrap()))
        );
        assert_eq!(
            log.field("dns.question.name"),
            Some(&SiemField::from_str(Cow::Borrowed("login.live.com")))
        );
    }

    #[test]
    fn test_parse_dns_answer_from_server() {
        // ["0E1C", "PACKET", "0000017DEDFE28D0", "UDP", "Snd", "10.20.0.6", "966f", "R", "Q", ""]
        let log = "22/12/2021 21:46:04 0E1C PACKET  0000017DEDFE28D0 UDP Snd 10.20.0.6       966f R Q [8081   DR  NOERROR] A      (5)login(4)live(3)com(0)";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(2));
        let log = parse_log(log).expect("Must parse the log");
        assert_eq!(log.service(), "DNS");
        assert_eq!(
            log.field("source.ip"),
            Some(&SiemField::IP(SiemIp::V4(2)))
        );
        assert_eq!(
            log.field("destination.ip"),
            Some(&SiemField::IP(SiemIp::from_ip_str("10.20.0.6").unwrap()))
        );
        assert_eq!(
            log.field("dns.answer.name"),
            Some(&SiemField::from_str(Cow::Borrowed("login.live.com")))
        );
        match log.event() {
            SiemEvent::DNS(event) => {
                assert_eq!(event.source_ip, SiemIp::V4(2));
                assert_eq!(event.destination_ip, SiemIp::from_ip_str("10.20.0.6").unwrap());
                assert_eq!(event.op_code, DnsEventType::ANSWER);
            },
            _ => panic!("No valid event type")
        }
    }

    #[test]
    fn test_parse_dns_answer_from_external_server() {
        // ["0E1C", "PACKET", "0000017DEDFE28D0", "UDP", "Snd", "10.20.0.6", "966f", "R", "Q", ""]
        let log = "22/12/2021 21:46:04 0E1C PACKET  0000017DECC585B0 UDP Rcv 8.8.4.4         624d R Q [8081   DR  NOERROR] A      (5)login(4)live(3)com(0)";
        let log = SiemLog::new(log.to_string(), 0, SiemIp::V4(8));
        let log = parse_log(log).expect("Must parse the log");
        assert_eq!(log.service(), "DNS");
        assert_eq!(
            log.field("source.ip"),
            Some(&SiemField::IP(SiemIp::from_ip_str("8.8.4.4").unwrap()))
        );
        assert_eq!(
            log.field("destination.ip"),
            Some(&SiemField::IP(SiemIp::V4(8)))
        );
        
        assert_eq!(
            log.field("dns.answer.name"),
            Some(&SiemField::from_str(Cow::Borrowed("login.live.com")))
        );
        match log.event() {
            SiemEvent::DNS(event) => {
                assert_eq!(event.source_ip, SiemIp::from_ip_str("8.8.4.4").unwrap());
                assert_eq!(event.destination_ip, SiemIp::V4(8));
                assert_eq!(event.op_code, DnsEventType::ANSWER);
            },
            _ => panic!("No valid event type")
        }
    }

    
}
