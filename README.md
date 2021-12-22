![Rust](https://github.com/u-siem/usiem-windns/workflows/Rust/badge.svg)
# uSIEM Windows DNS Server
Windows Server DNS parser for uSIEM

### Format

```
Message logging key (for packets - other items use a subset of these fields):
        Field #  Information         Values
        -------  -----------         ------
           1     Date
           2     Time
           3     Thread ID
           4     Context
           5     Internal packet identifier
           6     UDP/TCP indicator
           7     Send/Receive indicator
           8     Remote IP
           9     Xid (hex)
          10     Query/Response      R = Response
                                     blank = Query
          11     Opcode              Q = Standard Query
                                     N = Notify
                                     U = Update
                                     ? = Unknown
          12     [ Flags (hex)
          13     Flags (char codes)  A = Authoritative Answer
                                     T = Truncated Response
                                     D = Recursion Desired
                                     R = Recursion Available
          14     ResponseCode ]
          15     Question Type
          16     Question Name
```

### Examples

The logs that we are interested in are those that match "Snd" and "Q" or "Rcv" and "R Q" because "Snd" with "Q" is a query to another DNS server and the same with "Rcv" with "R Q"

```
4/21/2017 7:52:03 AM 06B0 PACKET  00000000028657F0 UDP Snd 10.2.0.1        6590 R Q [8081   DR  NOERROR] A      (7)example(3)com(0)
6/5/2013 10:00:32 AM 0E70 PACKET  00000000033397A0 UDP Rcv 10.161.60.71    5b47   Q [0001   D   NOERROR] A      (12)somecomputer(6)domain(3)com(0)
4/15/2014 3:16:00 PM 0710 PACKET  0000000028FB94C0 UDP  Rcv 69.160.33.71    8857 R Q [0080       NOERROR] A      .ns1.offeringsmislead.com.
4/21/2014 7:18:36 AM 0714 PACKET  000000002CC599A0 UDP  Snd 8.8.8.8         3434   Q [1001   D   NOERROR] A      .cdn-controltag.krxd.net.

22/12/2021 21:46:04 0E1C PACKET  0000017DEDFE28D0 UDP Rcv 10.20.0.6       966f   Q [0001   D   NOERROR] A      (5)login(4)live(3)com(0)
22/12/2021 21:46:04 0E1C PACKET  0000017DEDE1F920 UDP Snd 8.8.4.4         624d   Q [0001   D   NOERROR] A      (5)login(4)live(3)com(0)
22/12/2021 21:46:04 0E1C PACKET  0000017DECC585B0 UDP Rcv 8.8.4.4         624d R Q [8081   DR  NOERROR] A      (5)login(4)live(3)com(0)
22/12/2021 21:46:04 0E1C PACKET  0000017DEDFE28D0 UDP Snd 10.20.0.6       966f R Q [8081   DR  NOERROR] A      (5)login(4)live(3)com(0)
```
