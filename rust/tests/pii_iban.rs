// SPDX-License-Identifier: GPL-3.0-only
//! IBAN per the SWIFT IBAN registry (B-IBAN: T05, T21, F03).
//!
//! An IBAN is reported only when its country is in the registry, it has exactly
//! the registry length of that country and MOD-97 holds; `mod97` itself is
//! unchanged. Both rules find the value printed in one piece or in blocks of four
//! (letters included, `GB82 WEST 1234 …`), in upper or lower case. A SEPA
//! creditor identifier (`DE98ZZZ09999999999`) is no IBAN: its length is not the
//! registry length of its country, even where its digits pass MOD-97.

use patronus_ark::detectors::pii::{score::PiiMode, validators};
use patronus_ark::{
    ScanGateMatrix, SecurityCategory, SecurityGateway, SecurityLevel, SecurityScanResult,
};

const MODES: [PiiMode; 3] = [PiiMode::Strict, PiiMode::Balanced, PiiMode::Recall];

/// One valid IBAN per registry country with the registry length of that
/// country; the BBAN starts with the letter block `BANK`.
const REGISTRY: [(&str, usize, &str); 89] = [
    ("AD", 24, "AD03BANK2715411312388393"),
    ("AE", 23, "AE53BANK111220296520241"),
    ("AL", 28, "AL22BANK17040050284329605225"),
    ("AT", 20, "AT24BANK415442705969"),
    ("AZ", 28, "AZ97BANK38318200387312315133"),
    ("BA", 20, "BA26BANK296371075664"),
    ("BE", 16, "BE92BANK35079707"),
    ("BG", 22, "BG68BANK73615746512098"),
    ("BH", 22, "BH77BANK54002044781451"),
    ("BI", 27, "BI47BANK4146447584071863142"),
    ("BR", 29, "BR48BANK110583524427304922162"),
    ("BY", 28, "BY75BANK60547139011125459065"),
    ("CH", 21, "CH74BANK6890283749084"),
    ("CR", 22, "CR72BANK21353931568999"),
    ("CY", 28, "CY77BANK37302035149525473966"),
    ("CZ", 24, "CZ09BANK5129449340971155"),
    ("DE", 22, "DE82BANK68144546568699"),
    ("DJ", 27, "DJ86BANK6792073780334500577"),
    ("DK", 18, "DK20BANK2321458046"),
    ("DO", 28, "DO03BANK37322412307064784265"),
    ("EE", 20, "EE79BANK134326236222"),
    ("EG", 29, "EG12BANK295253445180048623470"),
    ("ES", 24, "ES70BANK2434404181279685"),
    ("FI", 18, "FI16BANK6891535011"),
    ("FK", 18, "FK67BANK3275631811"),
    ("FO", 18, "FO63BANK4646450314"),
    ("FR", 27, "FR33BANK5012261257101575372"),
    ("GB", 22, "GB69BANK14043101829743"),
    ("GE", 22, "GE17BANK48760198937329"),
    ("GI", 23, "GI90BANK494303840159202"),
    ("GL", 18, "GL92BANK8654002561"),
    ("GR", 27, "GR38BANK3209214574222456574"),
    ("GT", 28, "GT20BANK10464132938409207995"),
    ("HN", 28, "HN86BANK00034100129194872153"),
    ("HR", 21, "HR90BANK1546811546577"),
    ("HU", 28, "HU32BANK13945132067481710543"),
    ("IE", 22, "IE89BANK50784929022753"),
    ("IL", 23, "IL50BANK919050756080283"),
    ("IQ", 23, "IQ36BANK464281622482802"),
    ("IS", 26, "IS15BANK034046443455677215"),
    ("IT", 27, "IT83BANK5415157107091220702"),
    ("JO", 30, "JO73BANK8003479047925766752528"),
    ("KW", 30, "KW02BANK3604571615955874055700"),
    ("KZ", 20, "KZ44BANK435923170078"),
    ("LB", 28, "LB23BANK22035214498375522813"),
    ("LC", 32, "LC31BANK009804226373500122508948"),
    ("LI", 21, "LI25BANK4664649354185"),
    ("LT", 20, "LT20BANK618353523511"),
    ("LU", 20, "LU15BANK503267702342"),
    ("LV", 21, "LV49BANK5231059223603"),
    ("LY", 25, "LY06BANK13855269260617229"),
    ("MC", 27, "MC62BANK2034015274826607272"),
    ("MD", 24, "MD38BANK7012563024924745"),
    ("ME", 22, "ME13BANK70213186871413"),
    ("MK", 19, "MK85BANK12690500009"),
    ("MN", 20, "MN37BANK331322252274"),
    ("MR", 27, "MR36BANK2598307420251441517"),
    ("MT", 31, "MT61BANK40952150228129134576183"),
    ("MU", 30, "MU17BANK0242631190215474715074"),
    ("NI", 28, "NI28BANK75820423453344138858"),
    ("NL", 18, "NL57BANK4334552578"),
    ("NO", 15, "NO44BANK2379439"),
    ("OM", 23, "OM14BANK746936627236223"),
    ("PK", 24, "PK54BANK5201752221425539"),
    ("PL", 28, "PL30BANK29365034072648194279"),
    ("PS", 29, "PS55BANK331233360028125624040"),
    ("PT", 25, "PT65BANK16910320352018053"),
    ("QA", 29, "QA04BANK489472063090212201325"),
    ("RO", 24, "RO47BANK0049005106301791"),
    ("RS", 22, "RS52BANK66741297432654"),
    ("RU", 33, "RU80BANK5374335824334943044083230"),
    ("SA", 24, "SA45BANK3601530825401935"),
    ("SC", 31, "SC41BANK32306721804513332262055"),
    ("SD", 18, "SD71BANK4954965015"),
    ("SE", 24, "SE24BANK5031170026531444"),
    ("SI", 19, "SI29BANK11127235834"),
    ("SK", 24, "SK77BANK1045523221516550"),
    ("SM", 27, "SM08BANK6559250073515525025"),
    ("SO", 23, "SO77BANK310522806638535"),
    ("ST", 25, "ST46BANK11146276217830103"),
    ("SV", 28, "SV41BANK04238143985523161379"),
    ("TL", 23, "TL26BANK327190514123208"),
    ("TN", 24, "TN88BANK5703580633715490"),
    ("TR", 26, "TR84BANK222092539444669830"),
    ("UA", 29, "UA84BANK125587401054161955955"),
    ("VA", 22, "VA30BANK85104130236655"),
    ("VG", 24, "VG65BANK8654143905044556"),
    ("XK", 20, "XK35BANK583107413021"),
    ("YE", 30, "YE86BANK5341448234821455928444"),
];

/// SEPA creditor identifiers: `ZZZ` business code, national part; each passes
/// MOD-97 on its full value but none has the IBAN length of its country.
const CREDITOR_IDS: [&str; 4] = [
    "DE30ZZZ56545348553",
    "DE98ZZZ00001140336",
    "DE13ZZZ00001013632",
    "DE57ZZZ00001061146",
];

thread_local! {
    /// One scanner per test thread: the tests scan thousands of texts.
    static SCANNER: SecurityGateway = SecurityGateway::with_max_level(
        vec![SecurityCategory::Pii],
        SecurityLevel::L1,
        None,
        false,
    );
}

fn pii_result(text: &str, mode: PiiMode) -> SecurityScanResult {
    SCANNER.with(|scanner| {
        scanner.set_execution_gates(ScanGateMatrix {
            pii_mode: mode,
            ..Default::default()
        });
        scanner
            .scan_category(SecurityCategory::Pii, text)
            .into_iter()
            .find(|result| result.model == "native:pii")
            .expect("native PII result must be present")
    })
}

/// Texts of every IBAN span.
fn ibans(text: &str, mode: PiiMode) -> Vec<String> {
    pii_result(text, mode)
        .evidence_spans
        .into_iter()
        .filter(|span| span.label == "IBAN")
        .map(|span| span.text)
        .collect()
}

/// The IBAN in blocks of four with a shorter last block.
fn grouped(iban: &str) -> String {
    iban.as_bytes()
        .chunks(4)
        .map(|chunk| std::str::from_utf8(chunk).unwrap())
        .collect::<Vec<_>>()
        .join(" ")
}

#[test]
fn registry_length_per_country() {
    for (country, length, iban) in REGISTRY {
        assert_eq!(&iban[..2], country);
        assert_eq!(iban.len(), length, "{country}");
        assert_eq!(
            validators::iban_length(country.as_bytes()),
            Some(length),
            "{country}"
        );
        assert!(validators::mod97(iban), "{iban}");
        assert!(validators::iban(iban), "{iban}");
        assert!(validators::iban(&grouped(iban)), "{iban}");
        assert!(validators::iban(&iban.to_ascii_lowercase()), "{iban}");
    }
    for country in ["PH", "BD", "AR", "CO", "TH", "US", "ZZ", "XX"] {
        assert_eq!(
            validators::iban_length(country.as_bytes()),
            None,
            "{country}"
        );
    }
}

#[test]
fn length_other_than_the_registry_fails_even_when_mod97_holds() {
    for (country, length, iban) in REGISTRY {
        let bban = &iban[4..];
        // One character fewer and one more, with check digits that pass MOD-97.
        for bban in [&bban[..bban.len() - 1], &format!("{bban}7")] {
            let candidate = with_check_digits(country, bban);
            assert_ne!(candidate.len(), length);
            assert!(validators::mod97(&candidate), "{candidate}");
            assert!(!validators::iban(&candidate), "{candidate}");
        }
    }
}

#[test]
fn invalid_check_digits_and_shapes_fail() {
    for (_, _, iban) in REGISTRY {
        let wrong = format!(
            "{}{:02}{}",
            &iban[..2],
            (iban[2..4].parse::<u32>().unwrap() + 1) % 100,
            &iban[4..]
        );
        assert!(!validators::iban(&wrong), "{wrong}");
    }
    for value in [
        "",
        "DE",
        "DE89",
        "DEXX370400440532013000",
        "DE89-3704-0044-0532-0130-00",
        "DE89370400440532013001",
        "PH12345678901234567890",
    ] {
        assert!(!validators::iban(value), "{value}");
    }
}

#[test]
fn creditor_identifiers_are_no_iban() {
    for creditor in CREDITOR_IDS {
        assert!(validators::mod97(creditor), "{creditor}");
        assert!(!validators::iban(creditor), "{creditor}");
        for text in [
            format!("Gläubiger-Identifikationsnummer: {creditor}"),
            format!("SEPA-Lastschrift, Gläubiger-ID {creditor}, Mandatsreferenz M-2026-17"),
            format!("Creditor identifier: {creditor}"),
            format!("SEPA direct debit from creditor ID {creditor} on 1 Nov."),
        ] {
            for mode in MODES {
                assert!(ibans(&text, mode).is_empty(), "{mode:?}: {text}");
            }
        }
    }
}

#[test]
fn every_registry_country_is_found_compact_grouped_and_lowercase() {
    for (_, _, iban) in REGISTRY {
        for value in [
            iban.to_owned(),
            grouped(iban),
            iban.to_ascii_lowercase(),
            grouped(iban).to_ascii_lowercase(),
        ] {
            let field = format!("IBAN: {value}");
            for mode in MODES {
                assert_eq!(ibans(&field, mode), [value.clone()], "{mode:?}: {field}");
            }
            for prose in [
                format!("Bitte überweisen Sie auf {value} bis Freitag."),
                format!("Please wire the amount to {value} by Friday."),
            ] {
                assert_eq!(ibans(&prose, PiiMode::Strict), [value.clone()], "{prose}");
            }
        }
    }
}

#[test]
fn a_grouped_iban_ends_at_its_registry_length() {
    for (text, value) in [
        ("IBAN BE68 5390 0754 7034 und Name", "BE68 5390 0754 7034"),
        (
            "IBAN: AT61 1904 3002 3457 3201 1234",
            "AT61 1904 3002 3457 3201",
        ),
        ("IBAN: be68 5390 0754 7034 for rent", "be68 5390 0754 7034"),
        (
            "GB82 WEST 1234 5698 7654 32 BIC NWBKGB2L",
            "GB82 WEST 1234 5698 7654 32",
        ),
        ("NO93 8601 1117 947 kr", "NO93 8601 1117 947"),
    ] {
        for mode in MODES {
            assert_eq!(ibans(text, mode), [value], "{mode:?}: {text}");
        }
    }
}

#[test]
fn lookalikes_stay_negative() {
    for text in [
        // Glued to more characters: not a value of its own.
        "Ref GB82WEST12345698765432XYZ",
        // Mixed case is no printed IBAN.
        "IBAN: Gb82 West 1234 5698 7654 32",
        // A lowercase serial or hash prefix with a non-registry length.
        "serial ab12cdefghijklmn",
        "commit de89a7f3c2b1e4d5f6a7b8c9",
        // Blocks of four that fail MOD-97.
        "IBAN: GB82 WEST 1234 5698 7654 33",
        "IBAN: gb82 west 1234 5698 7654 33",
        // A country without IBAN.
        "Account PH12 3456 7890 1234 5678 90",
    ] {
        for mode in MODES {
            assert!(ibans(text, mode).is_empty(), "{mode:?}: {text}");
        }
    }
}

/// `country` + MOD-97 check digits + `bban`.
fn with_check_digits(country: &str, bban: &str) -> String {
    let rearranged = format!("{bban}{country}00");
    let remainder = rearranged.chars().fold(0u32, |remainder, c| {
        let value = c.to_digit(36).unwrap();
        let factor = if value >= 10 { 100 } else { 10 };
        (remainder * factor + value) % 97
    });
    format!("{country}{:02}{bban}", 98 - remainder)
}
