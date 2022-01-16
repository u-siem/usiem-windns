use usiem_windns::parsers;
use usiem::events::SiemLog;
fn main() {
    let now = std::time::Instant::now();
    for _i in 0..2_000_000{
        let log = "6/5/2013 10:00:32 AM 0E70 PACKET  00000000033397A0 UDP Rcv 10.161.60.71    5b47   Q [0001   D   NOERROR] A      (12)somecomputer(6)domain(3)com(0)";
        let log = SiemLog::new(log, 0, "10.0.0.0");
        let siem_log = parsers::parse_log(log);
        match siem_log {
            Ok(_log) => {
               
            },
            Err(_) => assert_eq!(1,0)
        }
    }

    println!("{:?} EPS",2_000_000_000 /now.elapsed().as_millis());

    //EPS: 698812 (11/02/2021)
    
}