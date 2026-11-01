//! CTCP extraction and encoding, and the outbound validators.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xdcc_core::proto::{
    BotNick, IrcMessage, LineBudget, LineContext, MAX_MESSAGE_LEN, OutboundLine, WireName,
    ctcp_privmsg, encode_ctcp, parse_ctcp, privmsg,
};
use xdcc_core_fuzz::{check_bound, measured};

/// Runs both builders on a fuzz-controlled body, and measures only the builders.
fn check_builders(nick: &BotNick, body: &[u8], budget: LineBudget) {
    let fits = 8 + nick.as_bytes().len() + 2 + body.len() <= budget.limit();
    let (plain, plain_bytes) = measured(|| privmsg(nick, body, budget));
    let (ctcp, ctcp_bytes) = measured(|| ctcp_privmsg(nick, body, budget));
    for (result, bytes) in [(plain, plain_bytes), (ctcp, ctcp_bytes)] {
        check_bound(bytes);
        match result {
            Ok(line) => {
                assert!(fits, "a line over budget was accepted");
                assert_eq!(bytes, line.as_bytes().len());
                let parsed = IrcMessage::parse(line.as_bytes());
                assert!(parsed.is_ok_and(|message| message.params() == [nick.as_bytes(), body]));
            }
            Err(_) => assert_eq!(bytes, 0, "a refused body allocated"),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let line = LineContext::new(usize::from(selector) * 4);
    let (parsed, bytes) = measured(|| parse_ctcp(body, line));
    check_bound(bytes);
    if let Ok(ctcp) = parsed {
        assert_eq!(ctcp.near_limit(), usize::from(selector) * 4 >= 480);
        let encoded = encode_ctcp(ctcp.tag(), ctcp.args());
        if let Ok(encoded) = encoded {
            let again = parse_ctcp(&encoded, line);
            assert!(again.is_ok());
            if let Ok(again) = again {
                assert_eq!(again.tag(), ctcp.tag());
                assert_eq!(again.args(), ctcp.args());
                assert!(again.final_delimiter());
            }
        }
    }

    let budget = LineBudget::reserving(usize::from(selector) * 3);
    let (accepted, bytes) = measured(|| OutboundLine::new(body, budget));
    check_bound(bytes);
    match accepted {
        Ok(line) => {
            assert_eq!(bytes, line.as_bytes().len());
            let bytes = line.as_bytes();
            assert!(bytes.len() <= budget.limit() && bytes.len() <= MAX_MESSAGE_LEN);
            assert!(!bytes.iter().any(|byte| matches!(byte, 0 | b'\r' | b'\n')));
        }
        Err(_) => assert_eq!(bytes, 0, "a refused line allocated"),
    }

    let (encoded, bytes) = measured(|| encode_ctcp(b"X", body));
    check_bound(bytes);
    if encoded.is_err() {
        assert_eq!(bytes, 0, "a refused CTCP body allocated");
    }
    let (name, bytes) = measured(|| WireName::new(body));
    check_bound(bytes);
    if name.is_err() {
        assert_eq!(bytes, 0, "a refused name allocated");
    }

    let (nick, bytes) = measured(|| BotNick::parse(body));
    check_bound(bytes);
    match nick {
        Ok(nick) => {
            assert!(!nick.as_bytes().iter().any(u8::is_ascii_control));
            check_builders(&nick, b"x", budget);
        }
        Err(_) => assert_eq!(bytes, 0, "a refused nick allocated"),
    }
    if let Ok(bot) = BotNick::parse(b"Bot") {
        check_builders(&bot, body, budget);
    }
});
