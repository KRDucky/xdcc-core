//! Filename sanitising: what every accepted name satisfies.

#![no_main]

use libfuzzer_sys::fuzz_target;
use xdcc_core::policy::{MAX_INPUT, NameRefusal, SafeName};
use xdcc_core::proto::WireName;
use xdcc_core_fuzz::{check_bound, check_safe_name, measured};

fuzz_target!(|data: &[u8]| {
    let (result, bytes) = measured(|| SafeName::from_bytes(data));
    check_bound(bytes);
    match result {
        Ok(name) => {
            check_safe_name(name.as_str());
            assert!(!data.is_empty() && data.len() <= MAX_INPUT);
            // Sanitising a result changes nothing.
            let (again, bytes) = measured(|| SafeName::from_bytes(name.as_bytes()));
            check_bound(bytes);
            assert_eq!(again.as_ref(), Ok(&name));
        }
        Err(error) => {
            if data.is_empty() {
                assert_eq!(error, NameRefusal::Empty);
            }
            if data.len() > MAX_INPUT {
                assert_eq!(error, NameRefusal::TooLong);
            }
            if data.is_empty() || data.len() > MAX_INPUT {
                assert_eq!(bytes, 0, "an oversized or empty name allocated");
            }
        }
    }

    // The same bytes as an offer's filename field, quoted or not.
    if let Ok(wire) = WireName::new(data) {
        let (viewed, bytes) = measured(|| SafeName::from_wire(&wire));
        check_bound(bytes);
        let direct = SafeName::from_bytes(wire.name());
        assert_eq!(viewed, direct);
        if let Ok(name) = viewed {
            check_safe_name(name.as_str());
        }
    }
});
