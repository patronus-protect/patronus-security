# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

This project is **pre-1.0**: any change to detection thresholds, the asset manifest, or public
result shapes may be breaking for downstream users, and is called out explicitly below.

## [Unreleased]

### Changed

- IP address spans (B-IP: T20 + baseline C1, TRIAGE 2026-W43 bucket 5, baseline P3/P9). An
  IPv4-mapped or embedded IPv6 address is one span (`::ffff:10.0.0.1`, `64:ff9b::198.51.100.1`), the
  zone ID and the CIDR prefix length are part of the span (`fe80::1%eth0`, `192.168.1.0/24`,
  `2001:db8::%eth0/128`); a prefix length out of range stays outside it (`10.0.0.0/123`). The IPv6
  rules no longer start inside a colon-delimited SWIFT MT or EDIFACT chain (`:28C::52D:`,
  `:60F::61F::62F:`, `BGM+380:21:3::90:FRET`, `LIN+1::1:550:::EA:20`), after `.`, `-`, `+` or a word
  character, and no longer report a value that a further `:`/`.` group continues, so an invalid mixed
  address (`2001:db8::256.1.1.1`) yields no sub-span; a SWIFT MT tag at the start of a line (`:25:`,
  ` :52A:`) and a field name (`IPv6:`) open a value. `validators::ip_address` checks the prefix length
  and zone ID and also rejects loopback, unspecified and multicast IPv4 inside a mapped address
  (`::ffff:127.0.0.1`, D-IP); the network-diagnostic filter strips zone ID and prefix and checks the
  mapped IPv4. Gold convention in `research/l1-pii/README.md`. **Detection change:** in `strict` and
  `balanced` IP spans grow by their zone ID and prefix length, mapped/embedded addresses replace their
  IPv4 sub-span, and IPv6 findings in SWIFT/EDIFACT chains and partial matches on invalid forms
  disappear. Dev: Gretel IP F1 90.6 → 96.7 (11 FP fewer, two SWIFT-tagged gold values now exact),
  presidio-analyzer IP tests 50.0 → 85.7, the P9 hard negative is no match.

- Payment card numbers need the IIN prefix and a length of their brand besides Luhn (B-PAN: T19 +
  F02, TRIAGE 2026-W43 bucket 4, baseline N1/P8). `pii_credit_card` validates with the new
  `validators::payment_card`: Luhn (unchanged), then `validators::CARD_IIN_RANGES` (Amex, Diners
  Club, Discover, JCB, Maestro, Mastercard incl. 2221–2720, Mir, UnionPay, UATP, Visa 13/16/19
  digits); 13 digits that open with a valid YYMMDD birth date (ZA ID number, KR resident registration
  number) and digits that open with a YYYYMMDD date (time stamps) are no card. The rule also no longer
  reports the digits right after `+` (`+44 20 1234 5678`, no sub-span either) or a `-`/`_` segment of
  a token (`xoxb-…-485275870833-…`). `checksums.ark` in `entity_map.yaml` lists `payment_card` instead
  of `luhn`; `scoreboard.py` ports it for the gold-gap report. **Detection change:** in `strict` and
  `balanced` (the same table gates the context-free card of `balanced`) card findings on phone
  numbers, EDIFACT/SWIFT stamps, token segments, ZA/KR IDs, IBAN BBANs without a card IIN and other
  Luhn-valid numbers without a brand disappear, and with them the card's secondary evidence inside such
  IBANs and its `overlap` entries next to phone numbers. Dev: card FP 95 → 11 (`strict`) and 59 → 8
  (`balanced`), every card TP and every Luhn-valid card gold value stays found; the presidio-analyzer
  hard negative `1748503543012` is no match.
- B-PAN follow-ups: CVV and card expiry now depend on a card that `pii_credit_card` reports
  (`payment_card` plus the position check, `context::has_payment_card`), not on any Luhn-valid
  number, and a `-`/`_`-joined card-field label of the card lexicon (`card-`, `card-number-`,
  `kartennummer-`, `karten-nr-`) is no token prefix, so the PAN after it stays found. **Detection change:** in
  `strict` and `balanced`, CVV and expiry findings next to a phone number or a brandless Luhn-valid
  number disappear, and compact or hyphen-grouped PANs after a hyphenated card-field label are found
  again.
- A CVV in a table column headed by a CVV label (`cvc`, `cvv`, … as a CSV or Markdown-table header)
  is reported without a card in the text; a `CVV: 123` field or a `cvv` key elsewhere still needs a
  reported card. **Detection change:** in `strict` and `balanced`, such column CVVs next to a phone
  number (found before only because the phone number passed Luhn) stay found, and column CVVs without
  any card number are new findings.

### Added

- Add ICAO 9303 check digits for German passport and identity card numbers (F08), one validator per
  document (weights 7-3-1, `A`=10 … `Z`=35): `validators::de_passport_number` (series `C F G H J K`)
  and `validators::de_identity_card_number` (series `L M N P R T V W X Y`), each for eight characters
  of the ICAO alphabet plus the check digit (`F12345671`, `L01X00T44`, the form presidio-analyzer and
  its tests use), the MRZ form of the nine-character serial plus its check digit (`C01X00T478`,
  `T220001293`, also inside `IDD<<T220001293<<…`) and the old numeric serial of ten digits
  (`1220001297`). The four new rules are scored-only like K05: `pii_passport_number_de_context_free`
  and `pii_identity_card_number_de_context_free` report a letter-led value without a field name at
  0.55, 0.80 with a document term (`Pass-Nr.`, baseline P6, `Reisepass-Nr.`, `Ausweis-Nr.`, `ID card
  no.`; `pass-nr` was already a K03 term of `pii.passport`, the rule that reads it was missing), and
  drop below both thresholds behind a nearer counter-context term; `…_legacy` reports the old numeric
  serial only with a document term or key. A bare value of a field that names something else stays
  silent (`DEA-Nummer: RN4135883`, `Codice Fiscale: …`, a `driver_license_number` column), and in
  `balanced`/`recall` passport and identity card findings compete with an overlapping finding of any
  other label (`overlap::DOCUMENT_LABELS`): a field-bound value of another label wins, so
  `Kundennummer K12345676` stays `CUSTOMER_ID` and `Passport number: Y22400855` stays a passport. The
  field-bound rules `pii_passport_number_de` and `pii_identity_card_number_de` keep their format check
  (`de_document_number`) in every mode, since a printed nine-character serial carries no check digit.
  `entity_map.yaml` classifies both validators as checksums with country `de` (M3: ARK 11 → 13 units,
  7 shared with Presidio); `scoreboard.py` ports them. `pii_l1.jsonl` gains 56 balanced/recall rows (at
  least 5 positives and 5 hard negatives per label in DE and EN). **Detection change:** none in the
  default `strict` mode (dev scoreboard +0.0 pp everywhere). In `balanced` and `recall` German passport
  and identity card numbers are new findings without a field name: dev passport F1 38.5 → 44.9
  (presidio_favored 0.0 → 34.3, ark_authored 70.3 → 76.9, neutral 38.0 → 37.7 with one new FP on an
  unannotated value), identity card F1 47.3 → 70.8, balanced L1 F1 +0.3 pp (DE +0.6 pp), no new
  hard-negative FP; 13_l1_golden_eval 734/734 positives, 638/638 hard negatives. Existing validators
  are unchanged.
- The foreign-field guard of F08 also covers the old numeric serial (`pii_passport_number_de_legacy`,
  `pii_identity_card_number_de_legacy`, PR #132 review): a key that names another value overrides a
  document term found by proximity, so `passport: archived` followed by `member_code: <ten digits>`
  reports no passport. **Detection change:** none in `strict`; in `balanced` and `recall` a
  checksum-valid ten-digit value under an unrelated key no longer becomes a passport or identity card
  finding because a document term stands nearby. A document key (`passport_no:`, `Ausweisnummer:`)
  and a key that holds a document term itself (`old passport number:`, new
  `context::key_holds_term`) still report it; validators are unchanged.
- Add VAT identification numbers for DE, AT, CH, FR, NL, BE, IT and ES (B01), one label and one
  check-digit validator per country: `VAT_ID_DE` (ISO 7064 MOD 11,10), `VAT_ID_AT` (UID `ATU`, Luhn
  variant), `VAT_ID_CH` (UID `CHE`, weighted mod 11), `VAT_ID_FR` (key `(12 + 3 × SIREN) mod 97` plus
  SIREN Luhn), `VAT_ID_NL` (mod 11 or ISO 7064 MOD 97-10, branch `B01`–`B99`), `VAT_ID_BE`
  (`97 − first eight mod 97`), `VAT_ID_IT` (Partita IVA: Luhn plus province office code) and
  `VAT_ID_ES` (DNI/NIE control letter or CIF control character), in `rust/src/detectors/pii/vat.rs`.
  The rules are scored-only like K05: an upper-case country prefix and the national printed form
  (`DE 136 695 976`, `CHE-100.155.212 MWST` without the suffix, `FR 40 303 265 045`,
  `BE 0403.019.261`) report without a field name at 0.55, 0.80 with a term of the new lexicon entry
  `pii.vat_identifier` (`USt-IdNr.`, `UID-Nummer`, `MWST-Nr.`, `VAT ID`, `TVA`, `btw-nummer`,
  `Partita IVA`, `NIF-IVA` …), and drop below both thresholds behind a nearer counter-context term.
  A bare Partita IVA (`pii_vat_id_it_proximity`, 11 digits without `IT`) needs such a term or key
  and joins the K07 competing labels, so it wins over a bare Steuer-ID on the same digits. A value
  that starts with a letter no longer counts as joined by `,` or a digit group before it
  (`context::stands_alone`, CSV cells); bare numeric values (Steuer-ID) are unchanged.
  `entity_map.yaml` classifies the eight validators as checksums (M3: ARK 3 → 11 units), maps DE
  and IT as `shared` and the six others as `ark_only` IDs; `scoreboard.py` ports the validators;
  the frozen E05 synthetic goldset stays byte-identical and lists the six new IDs as not generated.
  `pii_l1.jsonl` gains 214 balanced/recall rows (5 positives and 5 hard negatives per label in DE,
  EN and the national language). **Detection change:** none in the default `strict` mode (dev
  scoreboard +0.0 pp everywhere). In `balanced` and `recall` VAT IDs are new findings: dev
  `pii.de.vat_id` F1 98.9 (90/92 gold, 0 FP; the two misses are presidio-analyzer values with a
  failing check digit) and `pii.it.vat_code` F1 96.4 (27/29, 0 FP), balanced L1 F1 +2.1 pp, no new
  hard-negative FP on any dev corpus; 13_l1_golden_eval 706/706 positives, 610/610 hard negatives.
  Validators of existing labels are unchanged.
- `VAT_ID_FR` joins the K07 competing labels (B01 review): the eleven digits of a French VAT ID
  with a space after `FR` (`FR 40 303 265 045`, `FR 40303265045`) can also pass the context-free
  Steuer-ID, which kept a second, false `STEUERID` finding next to the VAT ID. The VAT ID is the
  longer value and wins like a Partita IVA; the other VAT IDs of B01 have no eleven-digit body and
  no competing overlap. Validators are unchanged. **Detection change:** none in `strict`; in
  `balanced` and `recall` such a French VAT ID reports one `VAT_ID_FR` finding, and the Steuer-ID
  rule's `matched_rules` entry names `overlap` (`longer_value`, `yields_to: VAT_ID_FR`).
- Implement the decided M2 rule and add `scripts/l1_presidio/scoreboard.py m2` (D-M2, decision of
  2026-10-21 in `research/l1-pii/README.md`, M2 row and fairness section). M2 holds only if it holds on
  both milestone families on their own, judged on `balanced`: macro-F1 is the unweighted mean exact F1
  over the `shared` and `ark_only` ids with gold on German rows of the family; `neutral` needs Presidio
  tuned + 15 pp, `presidio_favored` parity (tuned + 15 pp exceeds 100 there). `presidio_only` ids stay
  out of the macro average (listed as excluded) until `entity_map.yaml` marks them `shared`; a family
  without such gold does not hold. `m2` takes `--ark MODE=DIR` (balanced required) and `--presidio DIR`
  like `m1`, prints macro-F1, target and per-id F1 per family and mode, and exits 1 unless both family
  rules hold on balanced. `report` adds an M2 table per Ark mode and Presidio profile. **Detection
  change:** none; this is evaluation tooling only.
- Score the L1-PII scoreboard in the PII modes `strict` and `balanced` and report gold gaps of the
  frozen corpora separately (B-EVAL: T15 + T16, decisions of 2026-10-21 in
  `research/l1-pii/README.md`). `scripts/l1_presidio/scoreboard.py gate` runs `run_ark.py --pii-mode`
  for head and base in both modes (one build per side), checks that the runner confirms the mode, and
  fails on an F1 loss above 0.5 pp or a new hard-negative FP in either mode; stdout, the JSON report
  (`modes.<mode>.<split>`) and the per-commit results carry the mode, and strict predictions keep their
  cache layout. Milestones M1–M3 are judged on `balanced`: `m1` and `report` take `--ark MODE=DIR`
  (balanced required), print every mode and read the verdict from balanced. `report` adds a gold-gap
  section per corpus and entity for every engine: exact-span false positives whose value equals an
  annotated gold value of the same id elsewhere in the row, and gold values failing every checksum
  validator of their id (Python ports of `luhn`, `mod97`, `steuer_id`, `steuer_id_issued` in
  `CHECKSUM_PORTS`), with the number each engine still reports exactly; no metric changes.
  `research/l1-pii/scoreboard/baseline.md` adds the balanced numbers on dev (neutral exact F1 61.8
  balanced vs. 61.4 strict vs. 40.5 Presidio tuned; M1 on balanced 4/9 neutral, 5/12 presidio_favored)
  and the gold gaps (Gretel 21/53 PAN and 14/70 IBAN gold fail the checksum, Nano 65/82 PAN; 15 Ark and
  17 Presidio e-mail FP equal an annotated value elsewhere in the row). **Detection change:** none; this
  is evaluation tooling and a report only.
- Add DLP taxonomy v2 (K09). The entity groups stay unchanged; every credential/secret rule
  names a subtype within its group (`RuleMeta::subtype`,
  `patronus_ark::detectors::dlp::dlp::SecretSubtype`), and each of its `matched_rules` entries
  reports it as `subtype` next to `provider`: `api_key`, `access_token`, `secret_key`,
  `private_key`, `password`, `password_hash`, `generic_secret`, `session_token`, `signature` and
  `auth_url` (`dlp_credential_in_url`). Connection strings, webhook URLs, OTP secrets and seed
  phrases become the subtypes `connection_string` (`CREDENTIAL`), `webhook_url`
  (`SECRET_TOKEN`), `otp_secret` (`CREDENTIAL`) and `seed_phrase` (`CRYPTO_KEY`) for the rules of
  G01, P08, G08 and C01 instead of new groups. `research/dlp/entity_map.yaml` drops the planned
  groups `CONNECTION_STRING`, `WEBHOOK_URL`, `OTP_SECRET` and `SEED_PHRASE` and lists the subtypes;
  the gitleaks webhook rules map to `SECRET_TOKEN`. The result schema documents the taxonomy and
  the L1 rule catalog shows the subtype per rule. **Detection change:** none; spans, labels and
  scores are unchanged, `matched_rules` entries gain the `subtype` field.
- Add overlap resolution for DLP secret findings and DLP vs. PII double labels (K08). Overlapping
  credential/secret spans keep one span: a span that only adds quotes or a trailing `;`/`,` to a
  tighter span of the same tier gives way to it; a fixed-format match strictly inside a longer
  fixed-format value of another rule (a WIF-shaped Base58 run inside a Stripe key, OAuth token or
  JWT), or a keywordless match inside a longer secret value, is a substring artefact; then the tier
  decides (provider/key material > platform tokens > password hashes > structural credentials >
  generic assignments; `patronus_ark::detectors::dlp::dlp::overlap_tier`), within a tier the
  stronger validator, then the registry order. Suppressed matches stay in `matched_rules` with
  `suppressed_by`; `run_ark.py` attributes a range to the rule that kept it. A generic key that is
  the userinfo of a URL (`https://token:…@host`) belongs to the URL credential. When one request
  scans DLP and PII on the same text, PII L1 spans overlapping a DLP secret span are dropped from
  the PII evidence (URL passwords read as e-mail local parts, Slack token digits read as card
  numbers); the PII decision stays. **Detection change:** fewer DLP spans (generic `env`/assignment
  spans around provider tokens and JWTs, WIF artefacts inside other keys, the host after an empty
  URL password), tighter generic spans without quotes, URL passwords instead of the whole URL under
  a `token:` userinfo, and fewer PII spans in combined DLP+PII scans.
  `dlp_btc_wif` now validates Base58Check (mainnet version byte `0x80`, a secp256k1 scalar in
  range, the `0x01` flag for compressed keys); scoring stays at format strength. **Detection
  change:** WIF-shaped strings with an invalid checksum (documented example and test fills, random
  Base58 runs inside hashes, Stripe keys, OAuth tokens and JWTs) are no `CRYPTO_KEY` findings.
- Add a DLP rule prefilter (K07) so that the rule set scales to 200+ rules. One Aho-Corasick pass
  finds the prefilter keywords of all rules (`RuleMeta::keywords`, ASCII case-insensitive); a rule
  without a keyword in the text does not run. The keywordless rules get a structural prefilter
  (`RuleMeta::value_run`: 24 alphanumerics for `dlp_discord_token`, 51 Base58 characters for
  `dlp_btc_wif`). Rules whose matches start at most 64 bytes before a keyword and that cannot run
  on through a wide class are tried only at those positions, in text order, with an anchored probe;
  this takes `dlp_generic_credential_assignment` (Unicode `\b` on non-ASCII text) from about 6.5 ms
  to 0.2 ms per 100 KiB of code. Every gate is proven from the rule's regex syntax tree at pipeline
  construction (`patronus_ark::detectors::dlp::prefilter`); a rule without a proven gate runs on the
  whole text and fails `rust/tests/dlp_rule_prefilter.rs`, so new rules must declare keywords.
  Texts with LONG S or KELVIN SIGN, which `(?i)` matches for `s` and `k`, run every rule on the whole
  text. Native DLP time on 100 KiB benign code drops from about 9.4 ms to 3.2 ms (in-process,
  release build). **Detection change:** none; the matches equal a full scan on all goldens, the rule
  fixture and keyword-dense random texts.
- Add a DLP score model and the DLP output modes `strict`, `balanced` and `recall` (K04), on the
  PII score model: every DLP rule declares a base (1–100 points for its regex form); a finding
  scores base plus validator strength (checksum 35, structure 25, format 15, none 0) plus its
  context. A rule that captures the value behind a field name of its own adds 25; a secret without
  a field name (provider tokens, wallet and PEM keys, JWTs) takes the nearest DE/EN term on its
  line with the PII proximity rules: a credential term of `anchor_lexicons/dlp.json` adds
  25/20/15, a nearer digest/hash/ID term (new lexicon entry `dlp.digest_reference`: checksum,
  tx hash, Transaktionshash, Prüfsumme, commit SHA, sha256, UUID …) subtracts 30. The mode is a new
  execution gate: `ScanGateMatrix.dlp_mode` (`DlpMode`), Python `execution_gates={"dlp_mode": …}`
  and Ark API `gates.dlp_mode`; unknown names are rejected. `balanced` (0.50) and `recall` (0.30)
  keep the `strict` spans that reach the threshold, after the same overlap resolution, and report
  `score` and `context` in `matched_rules`; a bare `0x` + 64 hex value scores 0.40 and next to
  `tx hash` 0.10. `run_ark.py` takes `--dlp-mode`, and the DLP scoreboard reports P/R curves (exact
  and overlap P/R/F1 and hard-negative FP per score threshold) from a `recall` run on the carrier
  rows, without gating them. Detection change: none in the default `strict` mode; goldens,
  13_l1_golden_eval and the scoreboard profiles `default`/`extended` are unchanged. New `dlp_l1`
  goldens run in `balanced` (`dlp_mode`), and the rule catalog lists base, context source and score
  range per DLP rule.
- Shared validator library `patronus_ark::detectors::validators` for DLP and PII rules: CRC-32 and
  the CRC32-Base62 suffix of GitHub/npm tokens, Base58/Base58Check, Bech32/Bech32m (BIP 173/350,
  configurable length limit, 5/8-bit regrouping), strict canonical base64 (standard, unpadded,
  URL-safe), DER TLV parsing with minimal-length and INTEGER checks, JWT header (`alg`, `typ`,
  unsecured `none`) and compact JWS parsing, Shannon entropy per character, character classes and
  token alphabets. Spec test vectors (CRC-32 check value, Bitcoin Core base58, BIP 173/350,
  RFC 4648, X.690) plus a cross-check against the golden generator are in
  `rust/tests/validators.rs`. The DLP entropy floor now uses the shared `shannon_entropy`.
  **Detection change:** none; no rule uses the new checks yet (F01–F09 build on them).

- DLP rule metadata v2: every rule in `DLP_PATTERNS` carries a `RuleMeta` (`provider`,
  `validator_strength` `checksum`/`structure`/`format`/`none`, prefilter `keywords`, `min_entropy`,
  `source_ref`, live/test severity via `test_prefixes`). Each `matched_rules` entry in the native
  DLP layer details now reports `provider`, `validator_strength`, `source_ref` and, for
  credential/secret rules, `severity` (`test` for Stripe `sk_test_`/`rk_test_` keys, otherwise
  `live`). `research/dlp/rule_sources.yaml` lists the format source of every provider and key rule
  (gitleaks rule ID or vendor documentation; six legacy provider rules point to the F/T task that
  documents them), and the L1 rule catalog renders provider, validator strength and source.
  `DlpPattern` gains the public `meta` field. **Detection change:** provider, key and JWT rules
  drop values with a Shannon entropy below 3.0 bits per character (synthetic values drawn from a
  handful of characters); all golden positives and dev positives stay above the floor. Spans of
  all other matches are unchanged.

- `scripts/l1_dlp/baseline_report.py` scores ARK, gitleaks, TruffleHog and detect-secrets on one
  frozen DLP split with the scoreboard metrics and prints the tables of the new E14 baseline report
  `research/dlp/scoreboard/baseline.md` (untyped and per-group P/R/F1, hard-negative FP per
  variant, FP/MB, recall per secret entity) plus ARK error buckets per rule (hard-negative FP,
  missed and boundary gold spans, benign-code FP). The report adds the dev measurements, the
  latency comparison, a static coverage matrix against Google Cloud DLP and Microsoft Purview and
  TRIAGE candidates. **Detection change:** none; this is evaluation tooling and a report only.
- Add FR/ES/IT/NL field names to the existing PII anchor rules (T26, TRIAGE 2026-W43 bucket 12). Gretel's 660 FR/ES/IT/NL rows hid many field-bound values behind field names that only DE/EN rules knew. `pii_date_of_birth` (and its written-date variants) now accepts `date de naissance`, `né(e) le`, `fecha de nacimiento`, `nacido/nacida el`, `data di nascita`, `nato/nata il`, `geboortedatum`, `geboren op`; `pii_customer_id` `numéro/ID/identifiant de client`, `référence client`, `número/ID/código de cliente`, `codice/numero/ID cliente`, `klantnummer`, `klant-id`; `pii_employee_id` `numéro/identifiant d'employé`, `número (de identificación) del empleado`, `ID/codice/matricola dipendente`, `personeelsnummer`, `medewerker-id`; `pii_financial_account_number` `numéro de compte (bancaire)`, `número de cuenta`, `numero di conto`, `conto corrente`, `(bank)rekeningnummer`; `pii_credit_card_cvv` card-qualified security codes (`code de sécurité de la carte`, `cryptogramme visuel`, `código de seguridad de la tarjeta`, `codice di sicurezza della carta`, `creditcard-beveiligingscode`); `pii_ssn_us` `numéro de sécurité sociale`, `número de seguro social`, `numero di previdenza sociale`, `sociaal zekerheidsnummer`; `pii_passport_number_de` `numéro de passeport`, `número de pasaporte`, `numero di passaporto`, `paspoortnummer`, `reisdocumentnummer`; `pii_username` `nom d'utilisateur`, `nombre de usuario`, `nome utente`, `gebruikersnaam`, only with `:`, `=` or `#`. The field names also bind as structural keys (K04). The K03 lexicon entries of these labels in `anchor_lexicons/pii.json` gain optional `fr`, `es`, `it` and `nl` lists that the context engine and the lexical anchor scanner read. `pii_l1.jsonl` gains 64 rows (10 positives and 6 hard negatives each for FR, ES, IT, NL); the rule fixture probes the eight rules in the four languages. **Detection change:** `strict` (and the scored modes) report date of birth, customer and employee ID, account number, CVV, US SSN, passport number and username values behind these field names; dev corpora (strict, exact F1): Gretel L1 50.5 → 52.0 (date of birth 54.7 → 66.7, customer ID 37.5 → 46.7, passport 52.5 → 61.5, employee ID 75.0 → 79.0, account number 3.7 → 7.9, username 6.0 → 8.8), OpenPII Nano passport 3.7 → 10.7, synthetic DE/EU unchanged, no hard-negative FP. Generic security codes and usernames in prose stay silent. Validators are unchanged.
- Add secondary evidence to the default `strict` PII mode (T07, decision 2026-10-14, TRIAGE 2026-W42 bucket 4). `strict` keeps emitting both labels bit-identically (spans, class and confidence unchanged), but a `CREDITCARD` or `FINANCIAL_ACCOUNT_NUMBER` finding inside a reported, MOD-97-valid IBAN is now listed under the new `details.secondary_evidence` (`label`, `start_byte`, `end_byte`, `reason`: `iban_value` for the IBAN's own span such as `Bank account: GB82WEST12345698765432`, `iban_part` for a part such as the Luhn-valid BBAN of `DE18 4306 0967 1234 5678 00`; `primary_label`: `IBAN`). `overlap::SECONDARY_IN_IBAN` names the two labels. A card or account next to an IBAN, and the digits of an IBAN form whose check digits fail, stay primary; `balanced` and `recall` drop these findings instead (K07) and list nothing. Evaluations score primary findings only: `scripts/l1_presidio/run_ark.py` (scoreboard input) drops secondary spans and counts them as `secondary_spans` in its sidecar, `13_l1_golden_eval` and `pii_gold_hygiene.rs` skip them, and a `pii_l1` hard negative may annotate other real entities (`n(also=…)`, never its target label) that must be the only primary findings. `pii_l1` gains 24 strict rows (6 card/account positives next to a valid IBAN and 6 card/account hard negatives inside one per language); `l1_bilingual_rules.json` gains secondary probes for `pii_credit_card` and `pii_financial_account_number`; the three bucket-4 entries leave the gold-hygiene detector-FP list. **Detection change:** no finding is added or removed in any mode; in `strict` the PAN inside a valid IBAN and the account finding on an IBAN value are no longer scored. Scoreboard gate on the dev corpora PASS (no regression, no new hard-negative FP): card-number exact F1 42.5 → 42.8 (+0.3 pp), IBAN and account numbers unchanged, L1 F1 50.6 unchanged; `13_l1_golden_eval` 488/488 positives, 390/390 hard negatives. Validators are unchanged.
- Add cross-label overlap resolution to the scored PII modes (K07). Number labels compete for the same digits: the BBAN of a grouped IBAN or the digits of a `+49`/`+44` number can pass Luhn, and an account field can hold an IBAN or a card-shaped number. In `balanced` and `recall` the new `detectors::pii::overlap` resolves overlapping findings of two different labels among `COMPETING_LABELS` (`IBAN`, `CREDITCARD`, `FINANCIAL_ACCOUNT_NUMBER`, `STEUERID`, `PHONE`) to one; the first criterion that differs decides: an IBAN, the longer value, context that supports the finding's own label (field name, structural key or nearby support term: `Telefon: 0151 2345 6789 01`, `Kontonummer: 4111-1111-1111-1111`, `via telephone at 0157-09-316-8811`), a checksum, the higher score, the earlier rule. A finding inside a printed IBAN form (`DE64 7172 7958 4924 3372 11`, `FR76 7014 4858 …`) yields even when the IBAN's check digits fail or the grouped IBAN is not reported yet (T05). The loser leaves `evidence_spans`; its `matched_rules` entries stay and carry `overlap` (`reason`: `iban`, `longer_value`, `context`, `checksum`, `score`, `rule_order`, `iban_form`; `yields_to`: the winning label), and `class_name`/`confidence` follow the remaining findings. Other labels keep their overlaps (`EMAIL` and `USERNAME` on one address), and `strict` keeps both labels (decision T07). `pii_l1` gains 24 balanced/recall rows (6 card positives next to an IBAN or phone with Luhn-valid digits and 6 IBAN-form hard negatives per language); `l1_bilingual_rules.json` gains overlap probes for 5 rules. **Detection change:** none in the default `strict` mode (scoreboard gate on the dev corpora PASS, +0.0 pp, no new hard-negative FP; `13_l1_golden_eval` 476/476 positives, 378/378 hard negatives). In `balanced` and `recall` card numbers inside IBANs and phone numbers, and on account or phone fields, are no longer reported: on the dev corpora card-number exact F1 rises from 47.5 to 56.6 on Gretel Finance, 46.3 to 52.1 on the synthetic DE/EU set and 33.7 to 34.0 on OpenPII Nano, with card recall, IBAN, phone and account numbers unchanged (L1 F1 50.5 → 50.9 on Gretel, 48.1 → 48.3 synthetic). Validators are unchanged.
- Add obfuscation normalization with offset back-mapping to the PII L1 detector (K06). The new `detectors::obfuscation` builds a normalized view of a text with a byte map back to the original; when it undoes anything, the PII pipeline scans the view as well and adds every finding whose original span contains an undone obfuscation. In every mode it removes zero-width characters (U+200B–U+200D, U+2060, U+FEFF, soft hyphen) between two characters of a value, maps full-width forms to ASCII (a run with a full-width letter or digit, or a full-width separator such as `＠`/`．` between ASCII letters or digits) and undoes defanged separators `[.]`, `(.)`, `{.}`, `[@]`, `(@)`, `{@}`, `[:]` between ASCII letters or digits; emoji joiners and lone full-width punctuation in CJK prose stay. In `recall` only it also undoes spelled-out e-mail separators (`[at]`, `(ät)`, `at`/`ät`, `dot`/`punkt`, ` @ `, ` . `; without brackets or `@` the local part needs `.`, `_`, `-`, a digit or a dot word and the domain a common TLD, so `docs at example dot com` stays prose) and numbers spaced character by character (`D E 8 9 3 7 …`, eight or more characters, six of them digits); those findings score `SPELLED_OUT_PENALTY_POINTS` (10) below the plain form. Rules and validators run on the normalized value, the span, offsets and components are the original text, and the `matched_rules` entry names `obfuscation` (`zero_width`, `full_width`, `defanged`, `spelled_out`, `spaced_digits`). A normalized finding replaces a same-label finding it strictly contains and yields to any other, so spaced card digits that the card rule already accepts keep their plain finding. Gold convention T01 is unchanged for `strict` and `balanced`: spelled-out addresses stay hard negatives there, only `recall` rows may make them positives. `pii_l1` closes the 8 obfuscated known gaps and gains 28 rows; `l1_bilingual_rules.json` gains obfuscated probes for 8 rules. **Detection change:** `strict` and `balanced` now report e-mail and IP addresses, phone, card, IBAN, Steuer-ID and SSN values behind zero-width, full-width or defanged characters; `recall` also reports spelled-out e-mail addresses and spaced IBANs or passport numbers. `13_l1_golden_eval` 464/464 positives, 366/366 hard negatives; the dev corpora (strict, exact span) are unchanged (L1 F1 50.5, no new hard-negative FP), as they contain no such values. Normalization costs about 0.2 ms per 100 KiB in `strict`/`balanced` and 0.6 ms in `recall` when nothing is obfuscated. Validators are unchanged.
- Add context-free output of checksum-strong PII values in the scored modes (K05). In `balanced` and `recall` a value whose validator proves a real check digit no longer needs a field name: IBAN and card numbers already reported bare, and `PiiPattern` gains `scored_only` for rules that `strict` never runs (decision K02), reserved for unbound checksum rules. The first one, `pii_steuer_id_de_context_free` (base 20, checksum), reports a bare Steuer-ID of 11 digits or grouped `86 095 742 719`; it must pass the new `validators::steuer_id_issued` (the ISO 7064 MOD 11,10 check digit plus the BZSt digit distribution of issued IDs: one digit twice or three times, never three in a row, so `12345678903` or `47110815008` stay unreported) and stand alone, not after `+` or inside a longer number, range, decimal or slash path. It scores 0.55 bare, 0.80 after `Steuer-ID ist`, and 0.25 behind a nearer counter-context term (`Rechnungsnummer 86095742719`), below both thresholds; after its field name `pii_steuer_id_de` keeps the span. Golden fixture cases may name `pii_mode`; `pii_l1.jsonl` gains 24 balanced/recall rows (6 positives and 6 hard negatives per language), `entity_map.yaml` classifies `steuer_id_issued` as a checksum (M3 count unchanged: same unit). **Detection change:** none in the default `strict` mode (scoreboard gate on the dev corpora unchanged, 13_l1_golden_eval 442/442 positives, 352/352 hard negatives). In `balanced` and `recall` bare Steuer-IDs are new findings: on the synthetic DE/EU dev set Steuer-ID recall rises from 23 to 27 of 27 gold values, with no new false positive on any dev corpus (Gretel Finance, OpenPII Nano, TAB, synthetic). Validators are unchanged.
- Add structure awareness to the PII L1 detector (K04). A JSON or Python-dict key, a `key: value`/`key=value` line (YAML, INI, forms), an XML element or attribute (qualified by its parent element: `<customer id="…"/>`, `<employee><id>…</id></employee>`), a CSV header (`;`, `,`, tab, `|`) and the header row or key cell of a Markdown or HTML table now name the value they hold, like a field name right before it. The new `detectors::structure` parses these fields once per text (cached on the prepared text) and normalizes keys (`customerId`, `customer_id`, `Customer-ID` → `customer id`). In every mode a key binds a field-bound rule only if the rule accepts it as its own field name (also without spaces, `matrikelNummer`) and the value matches the rule's value form in full; validators and the rule's extra checks (generic `Kennung`, SWIFT, expiry coupling) decide as for a regex match, and a regex match of the same value keeps its evidence. Structural findings carry `matched_rules[].structure` (`json`, `kv`, `xml`, `csv`, `table`) and a `structure_key` component. For rules without a field name, a key of the K03 lexicon that names exactly the value is its context: +25 as field (`side: "key"`), −30 for a counter-context key such as a `Bestellnummer` column, and the required context of `pii_phone_de_national_proximity`; `context::key_context` exposes it. `pii_l1` gains 28 structured rows (DE/EN, 14 positives and 14 hard negatives: order columns, generic keys the rules exclude, invalid values under accepted keys) and closes 42 known gaps; `l1_bilingual_rules.json` gains structure probes for 15 rules. Detection change: `strict` now reports field-bound values in JSON, key-value, XML, CSV and table carriers that it missed before. On the dev corpora (strict, exact span) L1 F1 rises from 46.2 to 50.5 with no entity losing and no new hard-negative FP (employee ID +20.2, SSN +24.2, student ID +58.7, customer ID +9.5, passport +12.5 pp); on Gretel alone, values in CSV dumps whose gold leaves them unannotated cost precision (customer ID, SSN, CVV), so neutral EN F1 moves 50.3 → 49.3 while neutral overall gains 0.2 pp. Validators are unchanged.
- Add the PII context engine v2 (K03). The context of a finding is now two-sided: on the same line, before or after the value, the nearest term of a DE/EN lexicon decides. Support terms per label and counter-context terms come from `rust/src/detectors/anchor_lexicons/pii.json`, which gains phone reachability phrases (`erreichbar`, `Rückruf`, `call me at`, `can be reached at`), IP, MAC and payment-card terms, and six counter-context entries for numbers that are not PII (order, invoice, shipment/tracking, ticket/case, reference/booking/transaction, serial/article/version numbers); `detectors::pii::context` maps lexicon ids to labels. In `balanced` and `recall` an unbound value gains +25/+20/+15 for a support term up to 16/32/48 characters before (32 after) it, and loses 30 when a counter-context term is strictly nearer; field-bound rules keep their +25. A term does not count across a line break, a digit or `;`/`|`, and after the value not behind `,`/`:`/`=`/`#` or when it names the next value. `PiiPattern` gains `requires_context`: such a rule reports only with a support term and no nearer counter term, in every mode. The first one is `pii_phone_de_national_proximity` (base 20, format), a national number without a field name right before it (`Frau Weber ist unter 0176 90817263 erreichbar.`, `Rückruf bitte unter (030) 1234567`, `0221 4711230 (Handy)`). Golden rows may name `pii_mode` (`balanced`/`recall`), which `13_l1_golden_eval` uses for the scan; `pii_l1.jsonl` grows from 713 to 757 rows (12 positives and 12 hard negatives for the new rule, 10 positives and 10 hard negatives in `balanced` for counter-context). The rule catalog shows the context kind and the score range per rule. **Detection change:** `strict` reports national phone numbers next to a phone term that no rule found before (new rule `pii_phone_de_national_proximity`); every other `strict` finding is unchanged. In `balanced` and `recall` scores now include proximity context, and a value behind a nearer counter-context term can drop below the threshold (`Bestellnummer 4111 1111 1111 1111` 0.45, `Invoice no. 415-555-2671` 0.20). Validators are unchanged.
- Explain PII context scores and extend the K03 lexicon. In `balanced` and `recall`, every `matched_rules` entry of a PII finding now carries `context`: `bonus` and `penalty` points and, when a term decided them, its lexicon `anchor` (`field` for a field name bound by the rule), `side` (`before`/`after`) and `distance` in characters; `detectors::pii::context::evidence` returns the same. `pii.json` gains further DE/EN terms for the existing entries (`zu erreichen unter`, `Rückruf unter`, `credit card number`, `girocard`, `Kartennr`, `source_ip`, `Quell-IP`, `device address`, `bssid`, `Bestell-ID`, `invoice-id`, `Fallnummer`, `product number`, `Produktnummer`, `EAN`, `GTIN` …), and the L1 rule catalog lists the support anchors per label and the counter-context terms. `pii_l1.jsonl` gains 32 `balanced` rows (PHONE, CREDITCARD; DE and EN; 757 → 789) and `l1_bilingual_rules.json` balanced context and counter-context probes for eight rules. **Detection change:** in `balanced` and `recall`, values next to the new terms gain or lose context points like next to the existing ones; in `strict`, only the context-bound `pii_phone_de_national_proximity` consults the extended lexicon. Scores, spans and validators are otherwise unchanged.
- Add a PII score model and the PII output modes `strict`, `balanced` and `recall` (K02). Every PII rule declares a base (1–100 points for its regex form) and the strength of its validator: `checksum` (+35: Luhn, ISO 7064 MOD 97-10, Steuer-ID), `format` (+15) or `none` (+0); a value the rule binds to a field name adds 25. The score is the capped sum divided by 100. The mode is a new execution gate: Rust `ScanGateMatrix.pii_mode` (`patronus_ark::PiiMode`), Python `execution_gates={"pii_mode": "balanced"}`, Ark API `gates: {pii_mode: balanced}`; unknown names are rejected. `strict` is the default and unchanged. `balanced` (threshold 0.50) and `recall` (0.30) report the model score in `evidence_spans[].score` and `matched_rules[].score`, set `confidence` to the highest span score and drop candidates below the threshold. Every current rule scores at least 0.50, so both modes return the strict spans for now; the context engine (K03) and context-free checksum values (K05) add the candidates the thresholds gate. `count_validated.py check` fails when a declared strength contradicts `checksums.ark`, the L1 rule catalog lists strength, base and score per rule, and `run_ark.py --pii-mode` runs the opt-in modes. **Detection change:** none in the default `strict` mode; goldens, `13_l1_golden_eval` and ARK predictions on the dev corpora are bit-identical. `balanced` and `recall` change scores and `confidence` only.
- Add the M3 counting rule and `scripts/l1_presidio/count_validated.py` (T03). M3 now asks for 2× as many checksum-validated entities as Presidio 2.2.364 instead of 3×; a unit is one benchmark id per country whose validator computes a real check digit, format-only validation does not count. `entity_map.yaml` gains a `checksums` section that classifies every validator of the PII registry and every Presidio recognizer with `validate_result` (43, of which 35 compute a check digit, so the target is 70). `count_validated.py check` fails on unclassified validators, and with `--presidio` on a registry or version mismatch. Today Ark counts 3 (PAN, IBAN, Steuer-ID). No detection change.
- Add the L1-PII baseline report Ark vs. Presidio (E11). `research/l1-pii/scoreboard/baseline.md` scores Ark (strict) and Presidio 2.2.364 (`default`, `tuned`) on every dev gold set per source family, corpus and entity, states M1–M4 and the hard-negative criterion, and sorts the errors into buckets with candidates for the next TRIAGE. On dev, Ark leads on `neutral` (exact F1 52.7 vs. 40.5 tuned) and trails on `presidio_favored` (45.7 vs. 71.4, bare values without field names, grouped non-DE IBANs, IPv6 span boundaries); M1 holds for 3/9 shared ids on `neutral` and 4/12 on `presidio_favored`, and Ark hits 2 Presidio negative cases where tuned hits none. `scripts/l1_presidio/scoreboard.py report --gold DIR --engine NAME=DIR …` renders the tables (P/R/F1 per family, corpus and entity, hard-negative FP per family, M1 of the first engine against each other one). **Detection change:** none; this is evaluation tooling and a report only.
- Add Presidio-favored L1-PII gold sets and scoring per source family (E12). `scripts/l1_presidio/prepare_corpora.py --family presidio_favored` downloads the synthetic `synth_dataset_v2.json` of microsoft/presidio-research (MIT, pinned commit `7f568b6da8a5`) and the recognizer unit tests of presidio-analyzer 2.2.364 (MIT, 74 pinned test files), verifies their SHA-256 and freezes a group-atomic dev/holdout split with a SHA-256 manifest in its own directory pair (`presidio_favored/`). The test files are parsed with `ast`, never executed: cases on the default recognizer with literal text and an expected count or spans become rows scored only on the recognizer's ids (`scored_entities`), negative cases become whole-text hard negatives typed to that id. `research/l1-pii/entity_map.yaml` tags every gold source as `ark_authored` (`pii_l1`, `l1_bilingual_rules`, E05 synthetic), `neutral` (Gretel Finance, OpenPII Nano, TAB) or `presidio_favored`; `entity_map.py check` fails on an untagged source. The scoreboard reports P/R/F1 per family, gates the family aggregates like the other buckets, and `scoreboard.py m1` checks M1 on `neutral` and `presidio_favored` separately while `ark_authored` is reported only (fairness rule in `research/l1-pii/README.md`). The L1 gate gets a one-off `presidio-favored-corpora` step. **Detection change:** none; this is evaluation tooling only.

### Changed

- Split the PII L1 rules out of `rust/src/detectors/pii/pii.rs` into regional modules (K01): `common` (e-mail, IP, MAC, international phone), `intl` (IBAN, card number, CVV, expiry, SWIFT/BIC), `identifiers` (field-bound employee, customer, patient, student and applicant IDs, username, date of birth, account number), `de`, `us` and `uk`; the Dynamic-PII field anchors move to `context_anchors.rs`. Each rule is a `const` in its module, and `pii.rs` keeps `PiiPattern`, the pipeline and the `PII_PATTERNS` registry, which lists the 39 rules in the previous order because the first match sets `class_name` and wins same-label overlaps. `rust/tests/pii_registry_order.rs` pins that order, and `parse_native_patterns` in `scripts/generate_docs.py` (used by the rule catalog, `entity_map.py` and `count_validated.py`) resolves `module::CONST` entries. Rule ids, patterns, validators, goldens, `13_l1_golden_eval`, the generated docs and the ARK predictions on every dev corpus are bit-identical. **Detection change:** none; this is a refactor only.
- Move the PII L1 goldens (`pii_l1.jsonl`) to golden schema v2. Every row names the `pii_*` rule it exercises (`rule_id`), its carrier document (`carrier`: `line`, `prose`, `json`, `yaml`, `xml`, `csv`, `kv`, `table`), difficulty tags (`no_context`, `structured`, `obfuscated`, `ocr`) and whether it is a `known_gap`, a positive the detector misses today. The set grows from 140 to 713 rows: at least 5 gated positives and 5 hard negatives per label and language (DE/EN), every one of the 37 `pii_*` rules with a gated positive in both languages and a hard negative, and 89 known gaps (quoted JSON keys, CSV headers, table and XML cells, German `ist`/`lautet` after the field name, zero-width and full-width characters, parenthesised US area codes). The 140 existing rows keep their ids, text and spans. `13_l1_golden_eval` now checks PII coverage against `PII_PATTERNS`: it requires that the declared rule reported each gold span, prints coverage per `rule_id` (DE | EN) and per tag and language, and fails if a PII rule loses its last passing positive in a language or a known gap starts passing. `python/tests/test_pii_golden_schema.py` and `rust/tests/pii_golden_schema.rs` check the schema statically. **Detection change:** none; this is evaluation tooling only.

### Changed

- The DLP rules moved out of `rust/src/detectors/dlp/dlp.rs` into family modules under
  `rust/src/detectors/dlp/rules/` (`providers`, `crypto`, `credentials`, `hashes`, `identifiers`,
  `content`), each with its own validators. `DLP_PATTERNS` keeps its path and type and
  concatenates the families in the previous rule order. That order is pinned in
  `rust/tests/dlp_rule_registry.rs` because the first matching rule sets the result class.
  `scripts/generate_docs.py` and `scripts/measure_demo_pii_dlp.py` now read the rule modules.
  **Detection change:** none. Goldens, the golden eval and the full DLP output on the dev split
  are bit-identical.

### Fixed

- Fix the K07 `iban_form` suppression for findings that start at the printed IBAN form. In
  `balanced` and `recall`, an account field over a failing grouped IBAN (`Bank account: DE00 1234 …`)
  reported its country code and check digits as `FINANCIAL_ACCOUNT_NUMBER`, because containment
  excluded the form's first character. **Detection change:** none in `strict`; in `balanced` and
  `recall` such prefix findings now yield with `reason: iban_form`. Validators are unchanged.
- End phone spans before a line break and keep NANP trunk and `00` prefixes (T18, TRIAGE 2026-W43 bucket 3). `pii_phone_international`, the `+49`/`0049` form of `pii_phone_de` and `pii_phone_us` no longer separate digit groups with a line break (`\n`, `\r`, U+0085, U+2028, U+2029; other spaces such as U+00A0 still separate), so `+1-123-456-7890\n\n2` ends before the break and digits split across lines (`212\n555 0100`) are no phone number. `pii_phone_us` takes an optional trunk `1`/`+1` or a `00` international prefix in front of a 3-3-4 number into the span: `1-800-123-4567`, `1 (800) 123-4567`, `1.800.432.7716`, `001 415 555 2671`, `0044 207 946 0958`; with `+1` it now reports the whole number like `pii_phone_international`. The prefix is optional and needs a word boundary, so it only widens a number found before; a prefix alone (`1-800-FLOWERS`, `Kapitel 1-800`), `0044 20 7946 0958` and other `00` numbers without a 3-3-4 part stay unmatched. `0049 …` keeps its prefix as before. `pii_l1.jsonl` gains 12 positives and 10 hard negatives (DE and EN); `l1_bilingual_rules.json` gains exact-span probes for `pii_phone_international` and `pii_phone_de` and line-break hard negatives; the new `rust/tests/pii_phone_boundaries.rs` covers strict, balanced and recall. **Detection change:** phone spans with a trunk or `00` prefix start earlier, spans no longer run over a line break, and digits split by a line break are no longer reported; no new match. Scoreboard gate on the dev corpora PASS: phone exact F1 +6.6 pp (overlap unchanged), L1 exact F1 +1.0 pp (DE +0.2, EN +1.4; neutral +2.1, presidio_favored +0.3, ark_authored +0.0), no new hard-negative FP; `13_l1_golden_eval` 564/564 positives, 451/451 hard negatives. Validators are unchanged.
- Stop reporting EDIFACT, X12 and SWIFT MT elements, zero-padded IDs and 6-4 digit groups as phone numbers in strict (T17, TRIAGE 2026-W43 buckets 1 + 2). `pii_phone_international` and the `+49` form of `pii_phone_de` no longer start right after a letter or digit (`UNB+UNOC:3+520173321::2`, `NAD+BY+987654321`), after another `+` (`MOA+1++520173321`) or after a tag with a digit and `:` (`{86:+330105789456}`); a field name and `:` (`Tel.:+49 30 1234567`, `tel:+31…`) still opens a number, and `00` after `+` keeps an EDIFACT `COM+0049…:TE` number. `pii_phone_us` needs the area code set off by `)` or a separator, so `811228-9874` (Swedish personal number, 6-4), `0000012345` (`ST*850*0000012345~`, `:62F:/0000001234/`, SEC CIK) and other bare 10-digit runs are no longer matched; 3-3-4 and 3-7 forms (`(617) 5550183`, `020-1234567`) stay. `pii_l1.jsonl` gains 12 positives and 17 hard negatives (DE and EN); `l1_bilingual_rules.json` gains DE/EN hard negatives for the three rules, and its hard-negative test now covers PII; the new `rust/tests/pii_phone_precision.rs` covers strict, balanced and recall. **Detection change:** fewer phone findings, none of them gold on the dev corpora. Scoreboard gate on the dev corpora PASS: Gretel Finance phone FP 198 → 75 (−123), phone exact F1 65.7 → 77.3 with unchanged recall; all corpora phone exact F1 +9.6 pp, L1 exact F1 +1.1 pp (DE +1.1, EN +1.1; neutral +2.0, presidio_favored +0.0, ark_authored +0.6 with 49 fewer 6-4 phone FP), no new hard-negative FP; `13_l1_golden_eval` 552/552 positives, 441/441 hard negatives. Validators are unchanged.
- Report the parenthesized area code of a US phone number as part of the span (T04, TRIAGE 2026-W42 bucket 2). `pii_phone_us` opened with `\b`, which never holds before `(` after a space or at the start of a text, so `(415) 555-2671` was reported as `415) 555-2671` and missed every exact-span gold. A balanced `(NXX)` now starts the span in every mode; with `+1` in front the international rule keeps the full number as before. Unbalanced forms (`(415 555-2671`, `415) 555-2671`) keep their span. `pii_l1.jsonl` gates the two parenthesized known gaps and gains 10 positives and 10 hard negatives (5 each for DE and EN); `l1_bilingual_rules.json` gains an exact-span probe for `pii_phone_us`; the new `rust/tests/pii_phone_span.rs` covers strict, balanced and recall. **Detection change:** US phone spans with a parenthesized area code start one character earlier; no finding is added or removed. Scoreboard gate on the dev corpora PASS: phone exact F1 55.2 → 65.0 (+9.8 pp, overlap unchanged), L1 exact F1 50.8 → 52.4 (EN +2.9 pp; neutral +2.8 pp, presidio_favored +0.9 pp), no new hard-negative FP; `13_l1_golden_eval` 540/540 positives, 424/424 hard negatives. Validators are unchanged.
- `dlp_btc_wif` accepts testnet WIF keys and scores at checksum strength (F02). Base58Check now
  takes the version byte of mainnet (`0x80`; `5…`, `K…`/`L…`) or of testnet, signet and regtest
  (`0xef`; `9…` uncompressed, `c…` compressed), still with a secp256k1 scalar in range and the
  `0x01` flag for compressed keys; other version bytes, flags and scalars are no key. Testnet keys
  report severity `test`. `validator_strength` is `checksum` (was `format`), so the model score of
  a WIF key without context is 0.65 instead of 0.45. `dlp_l1.jsonl` gains 22 rows (testnet keys in
  faucet `.env`, `bitcoin-cli -testnet`/`electrum --testnet`, YAML, TOML, JSON, wallet code, log,
  chat and mail; testnet-shaped example/test fills, broken check values, references and the
  documented format as hard negatives; a checksum term as balanced hard negative).
  **Detection change:** checksum-valid testnet WIF keys are reported as `CRYPTO_KEY` (before: not
  matched), and in `balanced` a WIF key without a credential term is kept (before: dropped below
  the threshold); a nearer checksum, hash or ID term still drops it there. On the dev split the
  `strict` output is unchanged; `balanced` gains 39 gold WIF carrier spans and no other span.
- `dlp_eth_private_key` reports `0x` and 64 hex digits only in a key context (F01). The value
  needs a key term in its context, i.e. its line and up to five lines above it back to the
  previous hex value (private key, privkey, secret key, signing key, mnemonic, keystore,
  privater/geheimer Schlüssel; on the value's line or as its label also wallet, signer,
  accounts, pk, key, Schlüssel). A term that labels the value (only separators in between, also
  across line breaks) decides, so a hash, root, ID or chain-data label (tx hash,
  `transactionHash`, `blockHash`, Transaktionshash, checksum, Prüfsumme, Merkle/state root,
  Zustandswurzel, topic, salt, nonce, public key …) rejects the value. Without a label, a key
  term proper anywhere in the context supports the value, so a hash or ID word elsewhere in the
  sentence does not veto it; otherwise the nearest term decides. A term after the value counts
  within 40 characters on its line unless it names the next field. The
  value must also be a secp256k1 scalar (1 ≤ k < n). The gate is a new `RuleMeta::context_gate`
  and applies in every DLP mode. `dlp_l1.jsonl` gains 20 rows (CLI flags, `DEPLOYER_PK`,
  wallet constructors, chat/mail context; tx/block hashes, event topics, CREATE2 salt, state
  and Merkle roots as strict hard negatives). **Detection change:** a bare 0x-64-hex value and
  one next to a hash, root or ID term is no longer reported, also in `strict` (before: every
  0x-64-hex value). On the dev split the output is unchanged (all 40 Ethereum carrier positives
  stay findings; benign code and documents had no such match).
- DLP prefix rules report a value only as a whole token (T01). The 20 provider rules with a
  fixed prefix (`sk-ant-`, `hf_`, `AKIA`, `ghp_`, `npm_`, `xoxb-` …), `dlp_eth_private_key`,
  `dlp_btc_wif` and `dlp_jwt_token` declare a token boundary (`RuleMeta::boundary`): the
  characters right before and after the value may be no `[A-Za-z0-9_]` and none of the provider
  alphabet (`-` for base64url-style tokens), and a value with a `+`/`/` neighbour inside a
  base64 run of at least 16 characters with upper case, lower case and digits is part of a blob.
  Escapes that end in a letter or digit still delimit a token (`\n`, `\t`, `\uHHHH`, `\xHH`,
  `%HH`). `dlp_openai_legacy` drops its `\b` anchors for the same check, so it also finds keys
  after `%3D` or `\n`. Key-anchored rules (`dlp_aws_secret_key`, assignments) are unchanged;
  checksum validation stays with F02–F05. `dlp_l1.jsonl` gains 28 rows (lockfile checksums,
  Docker digests, go.sum hashes, identifiers; escape-delimited positives). **Detection change:**
  a prefix token glued into an identifier (`load_hf_…`, `resolve_npm_…`, `CachedAKIA…Policy`), a
  hex run (Cargo.lock checksum, sha256 digest, ABI calldata) or a base64 blob (go.sum, npm
  integrity, data URI) is no longer reported. On the dev split this removes one benign-code FP
  (a JWT behind `ghs_…_` in a test fixture); F1 and hard-negative FP are unchanged.
- Keep each rule's own score in `matched_rules` for PII findings behind an undone obfuscation (K06). A full-width bare German IBAN reported `pii_iban_generic` with the 0.90 of `pii_iban_de` instead of its own 0.80; the recall-only penalty now applies to each rule's own score. Detection change: `matched_rules[].score` only, evidence spans and verdicts are unchanged.
- Annotate every real entity in the PII L1 golden positives and check gold values against the validators (T02). Positives in `pii_l1.jsonl` now also carry the card number next to a CVV (15 rows) or a card expiry (4 rows), the phone number in `pii_l1-email-pos-01` and the IBAN in `pii_l1-swift-code-pos-06`; `generate_l1_goldens.py` takes them as `also=(label, value)`. `rust/tests/pii_gold_hygiene.rs` requires that every gold value passes a validator of its label (known gaps only for `CREDITCARD`, `IBAN`, `STEUERID`) and that every other L1 finding on a positive is gold or a listed detector FP. The seven Luhn-invalid `credit_card` values in `dynamic_pii.jsonl` are marked `"checksum_valid": false` and no longer count as L1 gold in `12_l1_pii_fixture_eval` (now 69 TP, 0 FP, 2 FN); the L3 NER still sees them. Validators are unchanged. **Detection change:** none; this is evaluation tooling and gold data only.
- Score `rust/examples/12_l1_pii_fixture_eval.rs` on character offsets. It compared the UTF-8 byte offsets of `native:pii` spans with the code-point offsets of `dynamic_pii.jsonl`, so every span after a non-ASCII character counted as one FP and one FN. Gold spans outside the text now abort the run, and the example's unit tests run with `cargo test`. **Detection change:** none; this is evaluation tooling only.
- DLP secret rules no longer report documented example and test values (T06). A shared check next
  to `is_secret_value` rejects values with a marker word: `EXAMPLE`, `SAMPLE`, `BEISPIEL` or
  `MUSTER` at the start or end of a word (not inside one, e.g. `resampler`), `TEST`/`TESTKEY`,
  `FAKE` or `DUMMY` as a whole word, or any marker repeated, so a marker inside random base62 does
  not count and the Stripe mode `sk_test_` is no marker. Values mostly made of repeated chunks or
  same-character runs are rejected for fixed-format provider, key, hash, JWT, signed-URL and
  session-ID rules, also when a generic rule (`dlp_env_var_secret`, assignments, URLs) captures
  the provider-shaped value. Values that count as low-variety only through a single sequential run
  (`AKIA1234567890ABCDEF`, hand-typed demo keys) and low-variety generic password/credential
  assignments are rejected only with explicit example context (example, sample,
  dummy, fixture, Beispiel, Muster … in the line or the three lines above; host names such as
  `example.com` do not count). PEM rules check the key body. Weak but real credentials
  (`password=abcabcabcabc`, a token with a `1234567890abcdef` run, a provider token with one
  repeated chunk) stay findings; new `weak` generators in `dlp_synth/rules.json` pin them, and
  per-provider DE/EN hard negatives were added to `dlp_l1.jsonl`. Their provider-format values are
  generator recipes with a new `fill` word (`patronus_ark.dlp_synth.recipes`,
  `patronus_ark::golden_recipes`), and the provider values of `l1_bilingual_rules.json` and the
  tests are assembled at test time, so no commit adds a token in an exact provider format.
  **Detection change:** on the dev carrier split, hard-negative FP on `doc_example`/`test_key` rows
  fall from 3 590 to 220 (−93.9 %) with unchanged positives; documented vendor examples such as
  the AWS documentation access key ID (`AKIA…EXAMPLE`) are no longer findings. Test fixtures that
  used fill values (`aB12aB12…`, `abcDEfGh…`) now use random values.
- Value-capturing DLP credential rules (`dlp_env_var_secret`, password and generic credential
  assignments, `dlp_credential_in_url`, `dlp_signed_url_signature`, `dlp_url_userinfo_password`,
  `dlp_csrf_token`, `dlp_bearer_token`, Basic auth and session cookies) no longer report
  placeholders or references (T07). Placeholders are `<…>`/`&lt;…&gt;`, masks (`********`,
  `xxxx-xxxx`), `TODO`, `CHANGEME`, `REPLACE_ME`, `BITTE_AENDERN` and all-upper or all-lower word
  sequences with a placeholder word (`YOUR_…_HERE`, `HIER_…_EINTRAGEN`, `YOUR-API-TOKEN`,
  `dein-api-token`, `INSERT_…`). References are `$VAR` (a `$` word with digits and without `_`,
  such as a password, stays a finding), `${…}`, `$(…)`, `${{ … }}`, `%VAR%`, `{{var}}`, `{%…`,
  `#{…}`, Terraform `var.`/`local.`/`data.`/`module.`, and environment accessors (`os.environ[…]`,
  `os.getenv`/`os.Getenv`, `System.getenv`, `Environment.GetEnvironmentVariable`, `ENV.fetch`/
  `ENV[…]`, `process.env`, `import.meta.env`, `env::var`, `env!`, `getenv`, `env(…)`). The check
  reads the text after the value, so captures cut at `(`, `[` or `}` are recognised, and it stops
  at quotes and escape backslashes (JSON-escaped notebooks). Real values next to references and
  placeholder-like real passwords (SCREAMING_SNAKE without a placeholder word, mixed case such as
  `YourDog2026!`) stay findings; two new `weak` generators pin them, and DE/EN hard negatives were
  added to `dlp_l1.jsonl` and `l1_bilingual_rules.json`. General code expressions as values stay
  with T03. **Detection change:** on the dev carrier split, hard-negative FP on `placeholder`/
  `env_ref` rows fall from 277 to 0 with unchanged positives (exact TP 1 183); benign-code dev FP
  fall from 372 to 367 (`your-client-secret-if-required`, `YOUR-API-TOKEN`), benign docs unchanged.
- DLP allowlist for documented values, test keys and further references (K06). Every secret rule
  drops vendor-documented example values listed in the new `research/dlp/documented_values.yaml`
  (AWS documentation keys, the Bitcoin wiki WIF example, the RFC 8410 Ed25519 key), which holds
  them only as SHA-256 of the normalized value with their source, and every JWT whose claims are
  the documented example claims of jwt.io (`sub` 1234567890, `name` John Doe) or RFC 7519/7515
  (`iss` joe, `exp` 1300819380), under any header and signature. Publicly known test keys (Hardhat
  Network/Foundry Anvil default accounts #0–#2) stay findings with `severity: test`. The
  value-capturing credential rules of T07 also drop Python `%(name)s` and `{name}`/`{0}`/`{name!r}`,
  Ruby/Puppet `%{name}`, Maven `@name@`, replace tokens `__NAME__`, cmd `!NAME!`, Concourse
  `((name))`, the YAML tags `!secret`, `!vault`, `!env_var` and CloudFormation `!Ref`/`!Sub`/…,
  secret-manager references (1Password `op://`, vals `ref+…://`, Azure `@Microsoft.KeyVault(…)`,
  AWS Secrets Manager/SSM ARNs, GCP `projects/…/secrets/…`, `/run/secrets/…`, also when the rule
  captures a part of the ARN), `null`/`None`/`nil`/`undefined`, the JKS default `changeit`,
  redaction words (`REDACTED`, `***REMOVED***`, `***ENTFERNT***`, `GESCHWAERZT`, `**None**`), the
  DE last words `…_EINGEBEN`, `…_AUSFUELLEN`, `…_EINSETZEN`, `…_HINTERLEGEN`, and values that only
  name the credential (`my-access-token`, `secret_token`, `SECRET_PASSWORD`, `MEIN_PASSWORT`,
  `auth.password`). Delimited names that look like the rest of a password (`{kqztrwx4711}`,
  `__Kx7pQ2vL9rT4__`) and words outside the credential-name vocabulary (`actual-secret`) stay
  findings. Inline suppression comments (`gitleaks:allow`, `pragma: allowlist secret`) are
  deliberately not honoured: in a DLP gateway they would let any sender exempt a secret.
  **Detection change:** on the dev split, benign-code FP fall from 374 to 350 and benign-docs FP
  from 4 to 3 (`None`/`null` defaults, `my-access-token`, `auth.password`, `**None**`,
  `Bearer secret_token`, a jwt.io RS256 documentation token); carrier spans are bit-identical
  (1 541), no span is new anywhere. 30 new `dlp_l1` goldens (DE/EN, 18 hard negatives, 12 positives)
  and eight hard negatives in `l1_bilingual_rules.json`.
- `scripts/l1_dlp/run_baselines.py run --tool detect-secrets` no longer aborts the whole run when
  a plugin raises on one file (a YAML date the detect-secrets YAML transformer cannot parse in the
  benign-code dev split). That file is listed under `errors` in `<output>.meta.json` (row `id`,
  file name, exception class only) with no spans, and every other file keeps its findings, as in
  `latency.py`. The metadata of all three tools now carries `errors`, and the summary line counts
  them. **Detection change:** none; this is evaluation tooling only.

## [0.1.10] - 2026-10-16

### Added

- Add the audited, high-precision Injection L1 governance rule catalog
  (`rust/src/detectors/injection/rules/governance_attack_regressions_0_1_9.json`, 18 rules such as
  `cross_tool_next_request`, `nested_system_override` and `german_policy_replacement`). It covers
  tool-output next-request overrides, nested system delimiters, German and English policy
  replacement, unrestricted modes, raw system-role boundaries, privileged tool calls,
  administrator grants and embedded new-task instructions. The end-to-end regression test
  `rust/tests/governance_attack_regressions.rs` pins every attack as terminal with its audited
  rule id and keeps nearby quoted, documentary and negated forms nonterminal.
  **Detection change:** Injection L1 now reaches a terminal `injection` decision for these
  governance attacks; the calibrated Injection L1 threshold is unchanged and the existing
  goldens and hard negatives are unaffected.

## [0.1.9] - 2026-10-16

### Added

- Add the `shell_command` category, backed by the revision-pinned
  [`patronus-studio/cat-shell-risk-commander`](https://huggingface.co/patronus-studio/cat-shell-risk-commander)
  model (Apache-2.0). It scores shell commands and scripts (POSIX, PowerShell, CMD) natively in the
  L1 phase and returns `shell_risk`/`safe` with the decision score, threshold policy and evidence
  spans. The model is downloaded and SHA-256-verified like the other assets, baked into the Docker
  image, and the category is accepted by the library, `ark-api`, the Cube worker template and
  `ark-coordinator`. **Asset manifest change:** new `shell_command/cat_shell_risk_commander` bundle.
  **Detection change:** new category only; existing categories are unchanged.
- Validate live IONOS scale-down from 12 to 8 Cubes and an end-to-end 8-to-9-to-8 Cube lifecycle,
  including worker setup, Coordinator/ALB routing, GPU inference, async scans, drain, and API removal.
- Add an external Triton watchdog that validates real GPU inference, with a hardened systemd timer and deduplicated TLS SMTP failure/recovery notifications. Credentials and deployment addresses remain in private host configuration.
- Add a reproducible Microsoft Presidio baseline runner for the L1-PII evaluation (`scripts/l1_presidio/run_presidio.py`) with a pinned environment and `default`/`tuned` (EN + DE) profiles. It writes predictions in the `external_pii_eval` format. **Detection change:** none; this is evaluation tooling only.
- Add an Ark PII-L1 prediction runner (`scripts/l1_presidio/run_ark.py`) that scans normalized Gold JSONL through the Python bindings and writes the same prediction rows as the Presidio runner, including per-span `score` and the original Ark label, with a timestamp-free metadata sidecar pinned to the native build. **Detection change:** none; this is evaluation tooling only.
- Add the L1-PII scoreboard (`scripts/l1_presidio/scoreboard.py`). `gate --head WT --base-sha SHA --dev DIR --holdout DIR --cache DIR` scores the Ark build of a checkout and of its base commit with exact and overlap P/R/F1 per entity, for all L1 entities and for DE/EN, counts predictions on hard-negative spans and exits 1 on an F1 loss above 0.5 pp or a new hard-negative hit. Base builds run offline from `git archive` into the cache; predictions are cached per source key, results per commit. `score` scores a single prediction file (Ark or Presidio). **Detection change:** none; this is evaluation tooling only.
- Add the L1-PII latency benchmark (`scripts/l1_presidio/latency.py`). `run` measures Ark through the Python bindings of a release build of the checkout (`ark`), the native Rust gateway (`ark-native`, `rust/dev/l1_latency_workloads.rs`) and Presidio `default`/`tuned` on fixed DE/EN workloads of one sentence, exactly 4 KiB and exactly 100 KiB, each engine in its own process, and reports p50/p95/p99 per size, the M4 check (100 KiB p95 ≤ 10 ms) and the Presidio/Ark ratio. Debug builds are refused. `compare` exits 1 when the Ark 100 KiB p95 grows by more than 10 % between two reports of the same machine. First VPS results are in `research/l1-pii/scoreboard/latency.md`. **Detection change:** none; this is evaluation tooling only.
- Run the L1 golden evaluation (`rust/examples/13_l1_golden_eval.rs`) in the CI `rust` job for both suites (`pii_l1.jsonl` and `dlp_l1.jsonl`, with `--locked`), so a positive span miss or a hard-negative hit fails the pull request, not only the L1 gate on the VPS. `scripts/tests/test_ci_golden_eval.py` keeps the step in place. **Detection change:** none; this is CI and evaluation tooling only.
- Add the L1-PII entity map (`research/l1-pii/entity_map.yaml`) that assigns every Ark PII label, every Presidio 2.2.364 entity and every external corpus label to one benchmark id with a scope (`shared`, `ark_only`, `presidio_only`, `semantic`), plus `scripts/l1_presidio/entity_map.py check` that fails when a registry label is unmapped or the map disagrees with the corpus manifest or the runner label maps. **Detection change:** none; this is evaluation tooling only.
- Add `scripts/l1_presidio/prepare_corpora.py`, which downloads the pinned Gretel Finance, OpenPII Nano and TAB sources, verifies their SHA-256, and freezes a group-atomic dev/holdout split (fixed seed, 60 % holdout) with a SHA-256 manifest and a `.ready` marker per directory; reruns must reproduce a frozen split byte for byte. Gretel Parquet is read by a dependency-free reader so the script runs in the Presidio venv. **Detection change:** none; this is evaluation tooling only.
- Add `scripts/l1_presidio/synth_goldset.py`, a synthetic DE/EU L1-PII goldset generator. It covers seven document types (letter, form, invoice, medical letter, JSON, CSV, support ticket) in German and English. Every benchmark id of `research/l1-pii/entity_map.yaml` appears in both languages, with checksum-valid values. Spans are code-point offsets, and hard-negative spans are tagged. Dev uses a public seed; the holdout uses a secret seed file. Both outputs are frozen with a SHA-256 manifest and `.ready`. The L1 gate creates them once. **Detection change:** none; this is evaluation tooling only.
- Define the L1-PII gold convention for reserved placeholder values (`research/l1-pii/README.md`): RFC 2606/6761 domains (`example.com`, `.invalid`, `.test`, `.example`, `.localhost`) and NANP `555-01xx`/`+1 000-000-0000` numbers are PII and gold positives; hard negatives exclude values by form only. `demo_pii_dlp_blind_en_tech.jsonl` row `cu-07` now expects `EMAIL` and `PHONE`, and the `pii_l1` hard negative `@localhost` becomes a non-reserved single-label host. Tests enforce the convention across `pii_l1`, `demo_pii_dlp*` and the E05 goldset. **Detection change:** none; Ark already reports these values.
- Add journaled IONOS fleet reduction with target planning, Coordinator/ALB handover, worker drain, result-retention checks, exact WireGuard peer removal, and protected API deletion. Add a one-Cube roundtrip for provision/setup/routing and verified scale-down.
- Keep the IONOS inventory and capacity planner read-only; use the dedicated fleet lifecycle commands for cloud mutations.
- Store secret values in the DLP L1 goldens (`dlp_l1.jsonl`) only as generator recipes (`{"gen", "seed"}`) plus a `<<secret:N>>` carrier template. Python (`patronus_ark.dlp_synth.recipes`) and Rust (`patronus_ark::golden_recipes`, `test-util` only) materialize identical text from the shared `dlp_synth/generators.json` with SplitMix64, checked by a fingerprint parity test. The 24 secret positives are migrated with an unchanged `13_l1_golden_eval` result (69/69, 46/46), and the checked-in file no longer contains checksum-valid tokens or any default DLP finding. No detection change.
- Add the L1-DLP benign-code corpus (`scripts/l1_dlp/benign_code.py`) for FP/MB. It uses 16 permissively licensed GitHub repositories, each pinned to a commit with its license and corpus SHA-256 in `benign_code_repos.json`, and leaves out secret-scanner repositories. Repositories are split 8/8 into dev and holdout. Each split covers code, lockfiles, minified JS, SVG, base64 and git logs. Key and credential files are skipped. `prepare` writes frozen split directories with a SHA-256 manifest, and `fp-per-mb` reports FP/MB in total and per kind, repository and rule. The data stays on the VPS. **Detection change:** none; this is evaluation tooling only.
- Add the L1-DLP benign-document corpus (`scripts/l1_dlp/benign_docs.py`) for false positives of content and document classes on German and English text. It has 12 sources in `benign_docs_sources.json`: Wikipedia articles (prose), German federal laws from `bundestag/gesetze` and 18F/GSA guides (government), and Wikimedia Foundation policies, legal pages and board minutes in German translation and English original (corporate). Each source is public domain or CC BY-SA, pinned to a git commit or MediaWiki revision ids, and has a corpus SHA-256. The split is by source; each split covers every language/genre pair, and no document or identical text is in both splits. Git sources fetch only the selected blobs, and MediaWiki revisions are checked against their titles. `prepare` writes frozen split directories with a manifest of license and SHA-256 per source, and `fp-report` reports FP/MB and the flagged-document rate per rule, language, genre and source. The data stays on the VPS. **Detection change:** none; this is evaluation tooling only.
- Add the L1-DLP baseline runner (`scripts/l1_dlp/run_baselines.py`) for gitleaks 8.30.1, TruffleHog 3.97.9 (`--no-verification`) and detect-secrets 1.5.0. It checks versions and binary SHA-256 against pins, runs each tool in its default profile on one file per row (named after the row path or carrier format), and writes one prediction format: code-point value spans with the native rule id and entities/groups from `research/dlp/entity_map.yaml`, no secret text, and a timestamp-free metadata sidecar. The per-tool normalization to the value span (gitleaks byte columns, TruffleHog `Raw`, detect-secrets prefix-only captures, URL userinfo, PEM blocks, escaped strings) is documented in `scripts/l1_dlp/README.md`. `check-entity-map` checks TruffleHog detector and detect-secrets plugin names against the pinned tools; the entity map now also maps TruffleHog `XAI` (xAI keys are `shared`) and the connection-string detectors to `credential.url_userinfo`. **Detection change:** none; this is evaluation tooling only.
- Add the L1-DLP ARK runner (`scripts/l1_dlp/run_ark.py`). It scans the same JSONL as the baseline runner through the Python bindings (`SecurityGateway(categories=["dlp"], max_level="l1")`, default rule profile, optional `--enable-rule` for default-off content rules) and writes the baseline prediction format: code-point value spans with the `dlp_*` rule id, `ark.<rule_id>` label and entities/groups from `research/dlp/entity_map.yaml`, plus the engine group and span score. The rule id is recovered from the `matched_rules` details of the scanner result that produced the span. A timestamp-free metadata sidecar pins the native build and counts spans per rule and group, unmapped rules and group mismatches. **Detection change:** none; this is evaluation tooling only.
- Add the L1-DLP latency and throughput benchmark (`scripts/l1_dlp/latency.py`). `bench` times ARK against gitleaks 8.30.1, TruffleHog 3.97.9 and detect-secrets 1.5.0 on four workloads built deterministically from the frozen dev split: single carrier rows, documents of exactly 4 KiB and 100 KiB (benign code with one carrier row per 4 KiB block) and a 10 MiB repository of benign-code files with carrier files. ARK is timed in process per document (p50/p95/p99) in a worker that loads a given build. The pinned baselines are timed as processes: start on an empty file, one run over every workload (scan and end-to-end MiB/s) and one invocation per document. detect-secrets runs single-process per file, because its CLI aborts on a file one plugin raises on. All processes are pinned to the same CPU, and reports carry numbers only. The scoreboard gate now times the head build against its base on the dev workloads in alternating rounds. It fails if the 100 KiB p95 rises more than 10 % (+0.25 ms slack) in two measurements, or if the head exceeds the H03 budget of 10 ms that the base keeps. The report is written to `latency.json`. **Detection change:** none; this is evaluation tooling only.
- Move the DLP L1 goldens (`dlp_l1.jsonl`) to golden schema v2. Every row names the `dlp_*` rule it exercises (`rule_id`), its carrier document (`carrier`), difficulty tags (`carrier`, `no_context`, `encoded`, `split`, `prose`) and whether it is a `known_gap`, a positive the detector misses today. Recipe placeholders can now encode the value (`<<secret:N|base64>>`, `hex`, `url`, `json`) or split it into ordered slices (`<<secret:N[a:b]>>`, one entity per fragment); Python (`recipes.materialize_fragments`) and Rust (`golden_recipes::materialize_fragments`) produce identical text. The set grows from 115 to 537 rows: at least 5 gated positives and 5 hard negatives per label and language (DE/EN), every one of the 59 `dlp_*` rules with a gated positive in both languages and a hard negative, and 27 known gaps (encoded and split secrets, anchors followed by `ist`/`is`/`lautet` or other words, quoted JSON keys, bare values without context). `13_l1_golden_eval` also requires that the declared rule reported each gold span, prints coverage per `rule_id` and per tag, and fails if a rule loses its last passing positive in a language or a known gap starts passing. The checked-in file writes the placeholder colon as `\u003a`, so it stays free of default DLP findings. **Detection change:** none; this is evaluation tooling only.
- Add the external DLP content goldens to the L1-DLP scoreboard (`scripts/l1_dlp/external_content.py`). The dev-only component `external/` holds the 214 Go and 13 Markdown files of gitleaks (source-code document labels; the Go files are also SQL negatives) and the SchemaPile-Perm SQL files with their first 250 statements as exact evidence spans. Both are normalized from the pinned sources and pinned by SHA-256, and the component is frozen like the other corpora. The contract in `docs/research/dlp-external-content-contract-0.1.8.md` defines when a document label attaches: a judged class needs an in-scope evidence span. The scope of a SQL file ends after its last selected statement, so SchemaPile precision and the exact-span score can now be reported (exact F1 88.4 %, recall 79.2 %, precision 100 %). The scoreboard scores the component in the extended profile and fails on a loss of more than 0.5 pp in external document F1 or SQL span F1. It refuses the component in a holdout split. The runner creates it once with the new gate step `external-corpora`. `scripts/measure_external_dlp_runtime.py` is replaced. **Detection change:** none; this is evaluation tooling only.
- Add the L1-DLP scoreboard (`scripts/l1_dlp/scoreboard.py`). `gate --head WT --base-sha SHA --dev DIR --holdout DIR --cache DIR` builds the release module of the head and the base commit offline into the cache (one build per hash of the detector sources), predicts with `run_ark.py` in the default profile and in an extended profile with every opt-in rule, and scores both frozen splits: exact and overlap P/R/F1 on value spans per entity group, untyped and per provider, provider attribution, FP per hard-negative variant, document-level P/R/F1 per content class, FP/MB on benign code and FP/MB plus flagged documents on benign documents. It exits 1 if a group, the untyped score or a content class loses more than 0.5 pp F1, a benign corpus gets more FP, or a hard negative gets a new FP; errors exit 2. stdout carries dev numbers only, the holdout appears as a verdict and its report stays in the cache. `score` and `compare` score any tool's predictions in the shared format and compare two reports. **Detection change:** none; this is evaluation tooling only.
- Add `scripts/l1_dlp/prepare_corpora.py`, the gate step that freezes the L1-DLP dev and holdout corpora (`--dev-out DIR --holdout-out DIR`). Each split gets the benign-code corpus, the DE/EN benign-document corpus and synthetic carrier rows from its own template families. Dev uses a public generator seed; the holdout uses a secret seed created once as `HOLDOUT/.seed` (mode 0600) and recorded only as a SHA-256 commitment. Every component has a SHA-256 manifest; the top-level manifest pins them and the files, and `.ready` is written last. A frozen directory is only rewritten with `--force`, and `--check DIR` verifies it. The script needs only the standard library and git, so it runs in the baseline venv without the native module. **Detection change:** none; this is evaluation tooling only.
- Add DLP carrier templates (`patronus_ark.dlp_synth.carriers`): 80 families of `.env`, YAML, JSON, TOML, HCL, XML, properties/INI, shell/CLI, Dockerfile, CI YAML, Jupyter, log, HTTP, code in eight languages and DE/EN chat, ticket and mail documents, split into disjoint dev and holdout families. Positives have code-point spans on the value only, with the applied escapes recorded. Every family also yields placeholder, env/template reference, documented example value and test key hard negatives; each split has every format in DE and EN, and encoded example and test values keep their detector shape (Base58Check prefix, `eyJ` JWT segments, PEM bodies) while only checksum or decoded structure is broken. A CLI writes the rows for one split and seed. No detection change.
- Add the synthetic DLP secret generator (`patronus_ark.dlp_synth`): deterministic, seedable generators for every secret and identifier `dlp_*` rule, including CRC-32-valid GitHub/npm tokens, Base58Check WIF keys, DER-parseable PEM keys (PKCS#8 Ed25519, PKCS#1, SEC1, DSA, OpenSSH), JSON-valid JWTs and ISO 7064-valid USt-IdNr. values. `dlp_synth/rules.json` maps each rule to its generators and probe carriers. Python and Rust (`golden_recipes`, `test-util` only) share the extended spec (version 2), and the output is pinned by fingerprint vectors. Tests check every value with independent offline structure checks and against its rule. No detection change.
- Add the DLP entity map (`research/dlp/entity_map.yaml`) that maps every `dlp_*` rule to gitleaks 8.30.1 rule IDs, TruffleHog detectors, detect-secrets 1.5.0 plugins and Google Cloud DLP infoTypes with `shared`/`ark_only`/`baseline_only`/`out_of_scope` scopes, enforced by a Rust test. No detection change.
- Add read-only IONOS Cube inventory and fleet capacity planning with protected-resource checks, identity validation, and redirect-safe credential handling. Provisioning and deletion remain explicitly unsupported.

### Fixed

- Require bounded payment or employment context for ambiguous PII L1 expiry and employee-ID fields, and explicit bank-field syntax for SWIFT/BIC matches. **Detection change:** bare expiry dates, generic product IDs, and Swift-language prose no longer emit these PII findings.
- PII L1 `pii_username` no longer treats the word after "login", "username" or "Benutzer" as an account name unless it follows an explicit assignment (`:`, `=`, `#`, "is", "ist", "lautet"). Prose such as "CLI login token" or "login-flow" and common UI words ("Username: required") are no longer PII findings. **Detection change:** unassigned forms such as "Login max.mustermann" are no longer L1 findings.
- Make IONOS fleet scale-down and round-trip recovery handle nested NIC inventory, provider
  target reordering, and the dynamically managed Coordinator WireGuard peer.
- Resume fleet changes safely after a provider accepted a target update before the local journal
  advanced, and use the test Cube's verified SSH host-key alias during drain.
- Persist the scale-up baseline before provisioning, reconcile accepted IONOS operations on resume,
  and make Coordinator/ALB registration idempotent across interrupted substeps.
- Replace deployment-specific names in the public IONOS profile example with explicit placeholders.

## [0.1.8] - 2026-09-20

### Added

- Added request-local classifier chunk overlap through the Ark API and Python queue API.
  `chunk_overlap_tokens` defaults to zero, is bounded to 64 tokens, and is applied consistently
  to shared L2/L3 chunks and decision-cache identity.
- Added direct L3 classifier execution when L2 is disabled, including canonical model inputs,
  request-local gates, independent tool-tag properties, and calibrated final decisions without
  fabricated L2 evidence.

### Changed

- Hardened Ark API and Coordinator request admission, ownership checks, event-stream access,
  worker recovery fencing, and request-local configuration snapshots.
- Split the Ark API entrypoint event handling, Unified L3 cache-key construction, and Python
  benchmark reporting into focused reusable modules while preserving their public behavior.
- Updated public documentation for category/level selection, offline requirements, deployment,
  result schemas, and the current API defaults.

### Fixed

- Preserve detector result events in the Ark API entrypoint after the event-module extraction.
- Require L3 model readiness when a request enables direct L3 while L1 and L2 are disabled.
- Preserve the pre-0.1.8 chunking path exactly when `chunk_overlap_tokens` is omitted or zero,
  including across internal 128-KiB tokenizer windows.

## [0.1.7] - 2026-09-13

### Added

- Added optional remote Unified L3 inference through a private Triton endpoint, with
  bounded HTTP requests, strict tensor validation, and pinned TensorRT deployment assets.
- Added bounded entrypoint overlap through `gateway.max_inflight_per_worker` (one by
  default, optionally two), allowing L1/L2 work while L3 is pending without releasing
  completion tracking or worker recovery fences. Documented controlled fleet benchmarks.
- Restored CLI regression coverage for hidden system-prompt disclosure, supplied
  Base64 instructions with verified decoded override/leakage signals, and destination-first
  secret handoffs. Includes bilingual cases, benign controls, rule gates, and source offsets.
- Restored governed prompt coverage for supplied encoded overrides, forged system personas,
  prior bypass agreements, cross-tool redirects, and explicit secret exfiltration.

- Added bilingual native Threat L1 rules with stable gates, source-bound action/target
  evidence, bounded matching, and the existing Threat taxonomy. Coverage includes remote
  and decoded execution, credential and session exfiltration, privilege and persistence
  risks, unsafe deserialization, metadata SSRF, and selected code/configuration relationships.
- Added DE/EN anti-refusal, policy-nullification, and memory-override Injection rules plus
  bounded Unicode-tag decoding with original-source evidence. Existing Injection scorer
  coefficients and operating point remain unchanged. New rules include positive, negative,
  gate, and offset regression coverage.

- Added a Redis-backed `ark-coordinator` service for Cube fleets, with bounded admission,
  fair adaptive batching, three concurrent slots per Cube, parent deadlines, and document-wide
  aggregation of category decisions and evidence offsets. Incomplete chunk/category coverage
  yields a degraded result rather than an allow decision.
- Added the versioned `ark-distributed-protocol` wire contract and authenticated worker batch
  inference endpoint, with prepared token-ID inputs, tokenizer/model/config fingerprints,
  per-chunk failures, and optional immediate unified L3 inference for promoted chunks.
- Added digest-pinned API and coordinator image workflows, resumable Cube/coordinator bootstrap
  scripts, private runtime configuration, deployment smoke checks, and an entrypoint benchmark.
- Added shared external Redis configuration and persistent overlapping fleet API keys for
  rotation, with atomic keyring recovery and migration of the interim key storage format.
- Added `POST /v1/scan/sync` to the worker and public multi-worker gateway for clients that
  need final per-category results and completion metadata in a single authenticated response.

### Changed

- Shared request-local lowercase/offset views, native windows and Unicode-tag decoding
  across native L1 detectors, and tokenized ordered catalog relations once per input.
  Added necessary-condition prefilters for four more Injection and five PII rules,
  retaining original regex captures, Unicode boundaries, validators and scores.

- Replaced the broad literal prefilter for system-prompt extraction with a necessary
  relationship check, retaining the original Unicode-aware regex and exact captures.

- Reduced native L1 text-preparation allocations for byte-length-preserving Unicode
  lowercase mappings and skipped action regex scans when their required local anchors
  are absent, preserving matching semantics and source evidence.

- The entrypoint assigns requests to free healthy workers through a bounded waiting queue.
  Worker status and admission epochs fence delayed submissions; interrupted jobs quarantine a
  worker until an authenticated idle recovery check succeeds. Readiness now includes worker health.
- Deferred distributed model fingerprint hashing until it is needed and bound fingerprints to
  loaded asset files; local startup reuses compatible tokenizers and shared embeddings without
  repeatedly hashing large assets. Unified L3 reuses prepared NTDB chunks and cached outputs.
- Replaced sorting-based memory-cache eviction with constant-time recency updates and eviction.
  Similarity candidate selection is bounded; encrypted derived outputs that can no longer be
  read are discarded and recomputed, and retention cleanup removes their index links.

### Fixed

- Reduced native PII L1 false positives by discarding sub-four-byte findings,
  rejecting unformatted numeric IDs and Unix timestamps as phone numbers, and
  accepting short CVV findings only alongside a Luhn-valid payment-card number.
- Build the Coordinator image against the complete workspace lockfile and validate the
  Docker build on pull requests before publishing deployment artifacts.
- Projected Unified tool-tag sigmoid outputs into independent binary property results,
  preserving property-specific chunk aggregation and joint L2/L3 decision context.
- Include the new workspace crates in the API Docker build and trigger image validation for
  distributed-protocol changes, so Cargo can resolve the complete workspace in the container.
- Added the coordinator and protocol test suites to CI and release validation, and build the
  entrypoint binary required by the Python integration tests. Added license-check exceptions
  for the two first-party GPL crates and resolved Clippy errors in distributed gate planning
  and the entrypoint. Refreshed generated Rust API docs and deployment documentation for the
  new worker scheduling behavior.
- Aligned package versions, image labels, release metadata, and bootstrap image checks at 0.1.7.

### Breaking

- Unified L3 tool-tag outputs are now exposed as independent binary property results rather
  than a mutually exclusive multiclass result. Consumers of tool-tag results must handle one
  `present` or `absent` result per configured property and its property-specific L2/L3 context.
- Classifier tokenization now requires NTDB v4 and compact mmBERT. Disjoint 128-KiB
  UTF-8 windows are tokenized once into shared 254-content-token chunks; L3 reuses
  those IDs with BOS/EOS and padding to 256 positions. Removed v2 execution,
  Hugging Face runtime fallbacks, and L3 re-tokenization. Chunk offsets track the
  source text and exact caches key token IDs. Existing v4 exports declaring 256
  content tokens now use the 254-token runtime budget; this changes L2 chunk boundaries.

## [0.1.6] - 2026-09-02

### Added

- Added local-only external PII corpus normalization and exact-span evaluation contracts, plus a
  text-free, hash-bound workflow for human-verified internal PII annotations. Checked-in fixtures
  validate schemas and metrics only; no external or private raw corpus is distributed. Pinned
  OpenPII-Nano, TAB, and Apache-2.0 Gretel Finance adapters establish a reproducible external gold
  inventory and an OpenPII native-L1 baseline split by language, scope, and entity. Deterministic,
  group-atomic selection manifests cap reports at 250 spans per corpus and metric class.
- Added a text-free local PII/DLP pre-annotation inventory builder for `v4.1` and related controlled
  corpora. Machine findings and Anchor-only hard-negative candidates are HMAC-bound and remain
  explicitly non-Gold until human review. Added derived, permissively sourced DLP document/content
  adapters for Go source documents and SQL statement boundaries without treating them as secret
  annotations or already measured end-to-end span scores.
- Added native PII and DLP L1 capabilities with validated exact spans, German and English
  anchor-bound identifiers, written birth dates, source/config/SQL/log detection, and non-blocking
  localized `layers[].details.l1_anchors` context facts. Added deterministic capability goldens,
  hard negatives, validators, and 100 KiB latency/evaluation tools.
- Added an implementation-blind bilingual demo benchmark covering 87 customer, personnel, and
  source-code documents with 204 expected PII/DLP/semantic spans and 19 hard negatives. Its
  augmented employee-identifier forms extend L1 with `PersNr`, employee/personnel number,
  staff-code, snake-case, OCR-field, and structured `EMP-*` variants while preserving existing
  customer, student, tax, and unanchored build-ID negatives.
- Added stable per-rule execution gates through Rust, Python, and Ark API configuration. Missing
  rule IDs inherit shared defaults; PII/DLP patterns use `pii_*`/`dlp_*` IDs and Injection uses its existing
  `ark.injection.*` IDs.
- Added a version-pinned native injection rule catalog derived from selected Prompt Armor rules.
  Catalog findings expose stable Ark/upstream rule IDs, exact byte and character spans, source
  revision, licence, family, severity, and descriptions. The first catalog closes high-specificity
  override, instruction-leak, boundary, Markdown exfiltration, and ES/FR/PT gaps without importing
  Prompt Armor's runtime or thresholds.
- Replaced the legacy Boolean L1 recognition/localization path with direct source-bound
  components for all 18 native Injection families and the five DLP operation/MCP producers.
  Regex, lexical, ordered-token and structural rules share the evidence contract; public
  classifications are projections of those matches. PII/DLP findings retain anchor/value
  components, and MCP retains tool/argument evidence. Existing rule/model gate IDs are preserved.
- Added complete bilingual reachability fixtures for all 39 PII and 59 DLP regex rules, native
  Injection families and MCP policy entries. Filled German/English gaps in contextual government
  identifiers, credential fields, jailbreak modes and agentic relations. Technical formats remain
  language-neutral. Normalized UTF-8 offsets map back to source; decoded containers are marked
  explicitly when exact decoded-character mapping is unavailable.
- Preserve overlapping PII findings across different labels; deduplicate overlaps only within
  the same label. Optional `explain` gates bounded diagnostic context anchors, not detection
  or the source-bound components of matched rules.
- Added four source-derived, high-precision injection relationships for sensitive-path exfiltration,
  authority-issued replacement instructions, decode-then-execute directives, and delimited
  replacement actions. Each finding retains its pinned Pipelock or PromptInject source and any
  secondary Garak reference. Labeled ROT13 and URL-safe Base64 payloads are decoded before the
  existing injection-signal evaluation.
- Added the injection `L1Candidate` contract. Positive rule signals become auditable `rule_match`
  features; overlapping or directly touching spans form one deterministic candidate and separated
  regions remain separate. Candidates expose spans, rule IDs, families, severity, explanations,
  provenance and the versioned calibrated L1 score.
- Added a native structural injection producer for override-plus-sensitive-disclosure
  relationships. It can create a candidate independently of the flat rule catalog and decomposes
  the decisive region into exact context-override, hierarchy-reference, disclosure-action, and
  sensitive-object features. Added German adaptations and nearby benign counterexamples for every
  new 0.1.6 catalog relationship; language-neutral Markdown exfiltration syntax is shared.
- Added a precision-first, monotone Injection L1 scorer calibrated on deterministic
  `injection_current` samples and the complete Hard-Benign development splits. Its artifact,
  dataset hashes, feature order, threshold, candidate/document metrics and reproducible tooling
  are versioned in the repository; the final holdout remains a separate release gate.

### Changed

- Injection L1 catalogs now scan their compiled regexes directly, removing the costly
  aggregate-regex prefilter while preserving findings, source-bound components, and provenance.
- Four expensive Injection context rules now skip impossible inputs using required-literal
  checks without Unicode word boundaries. Final matching retains Unicode case folding,
  word boundaries, captures, and original source offsets.
- Dynamic PII conditional labels now run as separate GLiNER inference groups scoped to chunks
  carrying the matching final source-pipeline class. Base labels stay stable, duplicate labels are
  removed from conditional calls, final L3 source classes supersede provisional L1/L2 classes,
  and duplicate entity spans keep the highest score across inference groups.
- The shared Rust/Python/Ark API DLP profile now enables credentials, secrets, authentication material,
  and sensitive-transfer context by default while gating broader business identifiers, metrics,
  source/SQL/dump/log content, MCP/runtime policy, and destructive operations behind explicit
  model/rule opt-ins.
- Dynamic PII now keeps overlapping hypotheses with different labels, reports all detected entity
  types through evidence and label scores, uses additive context-label bundles, and provides
  canonical `education` and `medical` mappings. Cross-text entity-cache matches no longer become
  live evidence; exact context-bound chunk caching remains enabled.
- Added `PATRONUS_L3_TTL_SECS=-1` to keep loaded L3 and Dynamic-PII ONNX sessions resident.
  The Ark API image and reference Compose deployment now use this setting to avoid the model
  reload latency spike on the first promoted request after an idle period.
- Changed the reference and OVH Ark API deployment to two FP16 workers limited to 2.5 CPUs each.
  On the canonical cold-cache HTTP benchmark this improved throughput from 6.761 to 7.728
  requests/s and reduced p50 latency from 440 ms to 168 ms versus three two-CPU workers. The
  Dockerfile now builds both API binaries explicitly and defaults its baked L3 assets to FP16.
- Changed native Injection L1 to publish one `native:injection_l1` aggregate instead of separate
  public results for every heuristic. The former detector model gates still control their internal
  producers. Accepted candidates expose evidence spans and `decision.final_result.source: "l1"`;
  rejected candidates keep their score and evidence without creating a finding and can be used by
  explicitly configured conditional L2/L3 gates. Registered external L1 detectors and DLP are
  unchanged.

### Breaking

- Dynamic PII first-entity previews are now emitted as non-authoritative `provisional` events
  instead of result-shaped events. Consumers must wait for the final `result` before acting. The
  obsolete `entity_cache_hit`/`entity_cache_hits` diagnostics were removed with cross-text reuse.
- `ScanGateMatrix` has a new public `rules` field, and native PII/DLP layer `details` can now
  contain `l1_anchors`. External Rust struct literals and consumers that assumed empty native
  details must account for these intentional pre-1.0 additions.
- Native Injection consumers that selected models such as `native:instruction_override` or
  `native:injection_rule_catalog` from public scan results must migrate to
  `native:injection_l1` and inspect `layers[].details.l1_candidates[].producers`, rule provenance,
  and the typed decision candidates. This intentional pre-1.0 result-shape change ships with
  0.1.6.

## [0.1.5] - 2026-08-29

### Added

- Added NTDB Package-v4/mmBERT loading for the exported
  `raw_text_to_joint_v3_chunk_promoter_union_v1` contract: the neural stack and LightGBM promoter
  score each chunk independently, only promoted chunks run through L3, and document decisions use
  the export's L2-only, L3-only, and Union aggregation modes and thresholds. Manifest/model
  feature dimensions are validated at load time. Package-v2 runtime types remain available but
  are deprecated.
- Added cache-backed Package-v4 parity evaluation for L2 probabilities, per-chunk promoter masks,
  and final document decisions, including multiclass and binary validation sets.
- Added pinned FP16 L3 selection via `PATRONUS_L3_PRECISION=fp16` for Injection, Threat,
  Sensitive Document, and the Lion Warden unified model.
- Added pinned FP16 Dynamic-PII/GLiNER selection. The image warmup now selects
  `onnx/fp16/model_fp16.onnx` from the current revision of the Edge bundle when
  `PATRONUS_L3_PRECISION=fp16` is set.
- Added request-local Ark configuration to the existing multipart `POST /v1/scan` endpoint. A
  request can override categories, maximum level, execution gates, metadata, and the NTDB
  operating point without restarting the API; omitted values retain the server/API-key defaults,
  and category overrides cannot exceed the worker or API-key scope. Existing text and multi-file
  uploads keep their original jobs contract.
- Added `decision.decision_candidate.chunk_evidence` for Package-v4 Union decisions. It records
  the aggregation method, every contributing L2/L3 chunk, and the decisive chunk(s), so clients
  can attribute the final document verdict without reconstructing it from layer diagnostics.
- Added `ark-api` YAML support for API-key default categories, Dynamic PII/GLiNER configuration,
  and the complete L3 scheduler policy (including per-pipeline overrides). Request-local gate
  policies use the same validated policy shape; invalid conditional gates and invalid scheduler
  bounds are rejected at configuration load time.
- Added native and HTTP throughput regression tools for the production-style gated
  injection/DLP/threat profile using unified L3. The native benchmark runs one Ark with parallel
  requests for at least 60 seconds, reports progress while consuming events, and uses a mixed
  workload averaging 100 KiB per request (96 KiB median) with repeated and varied content, small
  2–26 KiB requests, and 1 MiB spikes. It reports MiB/s, RPS, and latency percentiles and verifies
  completed requests, executed pipelines, levels, and the L3 model; Dynamic PII/GLiNER remains
  excluded because it requires a separate representative request-size profile.
- Added a CI throughput job that builds and installs a fresh release wheel, caches downloaded model
  assets, runs the gated unified benchmark without GLiNER, and publishes its JSON report.
- Added validated `pipeline.onnx_runtime` CPU session settings to `ark-api`. Intra-op/inter-op
  thread counts and spinning are applied before startup warmup, so every ONNX session uses the
  deployment's bounded thread policy; zero thread counts and unknown fields are rejected.
- Added explicit category and NTDB operating-point controls to the HTTP throughput benchmark so
  full injection/DLP/threat, no-threat, and `best_promote` runs record the configuration they test.

### Changed

- Re-pinned the Injection Package-v4/L3 bundle to Wolf Defender Small v2 and the three Tool Tags
  Package-v4 bundles to the current Husky Nose revision. Both model families now use the same
  immutable upstream revision for every runtime asset they supply.
- Pinned all nine published Package-v4/mmBERT L2 bundles (Injection, Sensitive Document, Tool
  Class, Tool Action, the three split Tool Tags, Routing, and Threat) to their immutable Hugging
  Face revisions. The unified L3 strategy uses the pinned public Lion Warden bundle, including
  FP16 selection; the former `-edge` repositories are no longer referenced.
- Changed Package-v4 routing to promote exclusively per chunk. `best_promote` uses the exported
  25% calibration operating point, while `best_f1` and `best_latency_in_f1` use the exported
  utility operating point. Post-L3 benefit and document-decider state are no longer part of the
  runtime contract; promoted chunks replace their L2 probabilities with L3 probabilities and
  non-promoted chunks retain L2 for export-defined Union aggregation.
- Changed Joint-v3 ONNX execution to the export's exact per-chunk tensor contract across Injection,
  Threat, Sensitive Document, Routing, Tool Class, Tool Action, and the split Tool Tags pipelines.
  Independent chunks remain parallelizable without document padding or attention-mask changes.
- Preserved the existing L3 strategy engine for Package-v4 promotions, including request-wide
  Early Exit, Representatives, Verify Representative, clustering, Exact Cache, and similarity
  propagation. Package-v4 changes which chunks are promoted, not how L3 schedules them.
- Changed Package-v4 final arbitration to use the export's default Union view while retaining
  L2-only, L3-only, and Union decision candidates for policy inspection. A rejected Union candidate
  returns the default class and is not overridden by an accepted L2-only candidate. Package-v2
  keeps its existing `decision_thresholds.json` arbitration unchanged.
- Changed the `ark-api` deployment to use the shared Unified L3 classifier for regular model heads
  and the separate Dynamic PII/GLiNER runtime. The Docker build bakes both asset bundles, and the
  reference build configuration now enables the production Injection/DLP/PII/Sensitive Document/
  Threat/Routing/Dynamic PII profile at L3 with one request worker per container.
- Changed `ark-api` scan input handling to accept both `text` and `content` multipart fields;
  request-local configuration is resolved once and snapshotted into each text or file job.
- Changed completed `ark-api` SSE request retention from five minutes to one minute.

- Optimized the CPU inference setup by updating the default ONNX Runtime Rust bindings to `ort`
  `2.0.0-rc.13` / ONNX Runtime 1.28 and making execution-provider selection feature-aware:
  accelerator builds prefer their configured provider and fall back to CPU, while CPU-only builds
  select the optimized CPU execution path directly instead of probing unavailable accelerators.
- Changed unified-L3 warmup to execute a real inference after loading the session, so Docker build
  warmup prepares both the embedded model assets and the runtime's first-inference path.
- Extended API readiness output with the available and actually active ONNX execution providers.

### Removed

- Removed NTDB `.kit` tokenizer loading and generation. Official Package-v4 models use the
  mmBERT-specific `.mmbpe` runtime, with `tokenizer.json` as the fallback.

### Fixed

- Fixed public gateway job polling to retain worker `evidence_spans` for every category. Native
  PII/DLP and Dynamic-PII consumers now receive labels, matched text, score, and byte/character
  offsets needed for redaction alongside classifier `decision_evidence`.
- Fixed x86_64 CPU inference parity for the verified German greeting and Dynamic-PII person-span
  cases by using the pinned FP16 ONNX graphs in production. On x86_64 deployments, build and run
  the API with `PATRONUS_L3_PRECISION=fp16`; the default quantized graphs remain suitable only
  where their output has been validated for the target runtime.
- Fixed Dynamic PII asset selection so a pinned FP16 GLiNER model is downloaded, baked, and loaded
  as one coherent bundle instead of validating it against the quantized model manifest.

- Updated Lion Warden, Wolf Defender Injection, Wolf Defender Threat, and Orca Sonar L3 assets
  to their public non-`-edge` Hugging Face repositories and current immutable revisions. FP16
  selection now uses the repositories' `onnx/onnx_fp16/model_fp16.onnx` layout, and Lion
  Warden's Sensitive Document head accepts its new `education` and `medical` classes.
- Fixed automatic Package-v4 model updates so the downloader parses freshly fetched manifests
  and the warmup validator through the Package-v4-aware parser before resolving or loading their
  runtime artifacts, including exported non-finite report-only metric values.
- Fixed warmup revision enforcement for official L2 packages: an existing manifest no longer
  suppresses an update when its `.patronus-revision` marker is absent or stale, or when its shared
  embedding matrix does not match the pinned manifest dimensions. Explicit local package
  overrides remain untouched.
- Fixed shared-embedder cache migration across encoder generations: embedding matrices with a
  mismatched manifest size are no longer reused, and asset downloads replace hard links or
  symlinks atomically instead of truncating another package's shared cache inode.
- Fixed an `ark-api` event-delivery race: scans that emit before the HTTP handler registers their
  request buffer now create that buffer in the dispatcher, preserving the event history for the
  subsequent SSE subscriber.
- Clarified that the built-in benchmark corpus contains synthetic historical regression fixtures,
  not the model-release validation splits; its F1 values are therefore not release-validation
  metrics.

- Prevented CPU-only builds from attempting to register an accelerator execution provider that was
  not compiled into the binary.

### Breaking

- Completed `ark-api` scan event streams are retained for one minute instead of five. Clients must
  begin consuming `GET /v1/scan/{request_id}/events` within that shorter window.

## [0.1.4] - 2026-08-18

### Added

- Added the public `PrivateNetworkDiagnosticHook`, which retains private and local IP predictions
  for diagnostics while filtering their evidence spans from network-diagnostic output.
- Added shared tokenizer caching and direct mmBERT token-ID handoff from compatible NTDB L2
  chunks to dedicated and unified L3 inference.
- Added `ark-api`, an ephemeral HTTP API around the security pipeline for self-hosted and
  Patronus-hosted deployment: `POST /v1/scan` accepts text and/or one or more files and returns a
  `request_id` per input, `GET /v1/scan/{request_id}/events` streams progress and per-category
  results over Server-Sent Events, buffering events so a client that only starts polling after a
  fast scan completes still sees the full history instead of a 404.
- Added YAML-based `ark-api` configuration, including per-API-key category scoping and gate
  overrides: `pipeline.gates` (and per-key `auth.keys[].gates`) deserialize directly into
  `ConditionalPipelineGate`/`GateExpression`, so the full metadata/prior-result condition tree and
  per-pipeline L3 policy overrides are configurable in YAML without a bespoke parser.
- Added a multi-stage `ark-api` Dockerfile that bakes model assets in at build time (via
  `ark-api --warmup-only`) and a `docker-compose.yml` reference deployment for self-hosting.

### Changed

- Changed compatible mmBERT NTDB runtime chunks to 254 content tokens so L2 tokenization can be
  reused safely by 256-token L3 models with their boundary tokens.
- Tightened native injection, DLP, and MCP relationship matching so actionable verbs, targets,
  and destinations must occur in supported request forms.
- Expanded Unicode-confusable normalization so mixed-script security signals are evaluated through
  an ASCII skeleton before a finding is emitted.

### Fixed

- Reduced false-positive native findings in source code, test names, logs, documentation, benign
  tool output, and ordinary developer-mode or network-diagnostic text.
- Prevented compatible L2 spans from being re-tokenized or silently truncated during L3 inference;
  incompatible or oversized handoffs now fall back to model-backed L3 rechunking.
- Allowed unified and dedicated L3 bundles to load a compact `tokenizer.mmbpe` when
  `tokenizer.json` is unavailable, while preserving the JSON fallback.
- Worked around a `serde_yaml` 0.9 bug deserializing recursive enums nested inside sequences (hit
  by `ark-api`'s conditional gate config) by routing YAML config parsing through `serde_json`.

### Breaking

- Native injection, DLP, MCP, obfuscation, and PII evidence decisions can change because matching
  relationships, Unicode-confusable handling, and post-prediction evidence filtering were updated.
- Compatible mmBERT NTDB packages now use 254 content tokens per runtime chunk instead of 256.

## [0.1.3] - 2026-08-11

### Added

- Added public post-prediction hooks for filtering non-actionable credential and local-path
  evidence while retaining model predictions for diagnostics.
- Added precision-first, real-corpus calibration data and a local sweep tool for general Dynamic
  PII labels, plus benchmark coverage for names, dates of birth, cities, and countries.

### Changed

- Expanded the default and document-aware Dynamic PII label sets with calibrated `first_name`,
  `last_name`, `date_of_birth`, `city`, and `country` entities, and recalibrated `date`.

### Fixed

- Reduced false-positive DLP and MCP findings for template `.env` copies, empty or placeholder
  secret assignments, and low-entropy credential values.
- Suppressed `person` evidence when a detected name is only a username inside a local filesystem
  path.
- Rejected loopback, multicast, unspecified, and truncated IPv6 candidates as PII, and rejected
  terminal metadata words and invalid zero postal codes as German postal addresses.

### Breaking

- Dynamic PII findings and native PII/DLP/MCP decisions can change because label sets, thresholds,
  evidence filtering, and native validators were updated.

## [0.1.2] - 2026-07-26

### Added

- Added compact `.mmbpe` tokenizer generation for compatible mmBERT byte-fallback BPE
  tokenizers during verified downloads and cached warmup. The original `tokenizer.json` remains
  the canonical fallback.
- Added German imperative variants to the native `instruction_override` L1 detector.

### Changed

- Added the structured `decision` envelope to model-backed classifier results. The envelope exposes
  the final Ark verdict, the canonical policy candidate, all typed L2/L3/Union candidates, Ark's
  calibrated recommendation, terminality, and minimal provenance.
- Restricted `decision` to terminal authoritative classifier results. Early L2 results with
  `l3_pending`, provisional events, and result-preview events now leave `decision` unset so
  downstream policy consumers can key on `result.decision.is_some()`.
- Extended compact tokenizer asset preparation beyond Granite `.kit` generation so supported
  mmBERT L2/L3 bundles can reuse hash- and version-invalidated generated artifacts.
- Changed classifier default arbitration to preserve a calibrated default-class confidence when
  the producing model exposes one, instead of always forcing `0.0`.

### Fixed

- Fixed promoted NTDB L2 fallback results so the final-decision threshold profile is still applied
  before publishing the fallback class.
- Fixed L2-only classifier arbitration so accepted candidates are selected from model label scores
  instead of the already defaulted top-level result.
- Fixed persistent `redb` cache handling to recreate a missing or externally deleted database file
  while still surfacing corrupt databases and active second-writer conflicts as errors.

### Breaking

- Removed the redundant NTDB L2 `details.raw_class_name` and `details.raw_confidence` fields.
  Consumers should read `decision.decision_candidate` and `decision.candidates[]` instead.
- Candidate arbitration data is no longer exposed as public `layers[].details.arbitration_*` fields.
  The public contract is the top-level `decision` envelope.

## [0.1.1] - 2026-07-26

### Added

- Added bundled NTDB final-decision thresholds for L2, L3, and weighted L2/L3 union arbitration
  across classifier pipelines.
- Added request-local `enqueue(..., ntdb_operating_point=...)` support for overriding the
  final-decision threshold profile on queued scans.
- Added `threat` validation samples to the built-in local benchmark.

### Changed

- Changed classifier final arbitration to accept L3 first, then a weighted L2/L3 union, then L2,
  and otherwise return the pipeline default class.
- Changed Python's `ntdb_operating_point` meaning to select the final-decision threshold profile;
  L2 promotion continues to use the NTDB package promote operating point and is not changed by
  that Python setting.
- Changed the default final-decision threshold profile to `best_f1`.

### Removed

- Removed `tool_class` validation samples from the built-in local benchmark fixture set.

### Breaking

- Classifier result decisions can change because calibrated final-decision thresholds now apply
  to L2, L3, and union arbitration.
- Benchmark comparisons against previous local runs are not one-to-one for `tool_class`, because
  the packaged benchmark fixture was removed and `threat` was added.

### Added

- Added `normalize_text(text, configs={})` as a pure text-normalization API for applying
  `canonical_security_text_v1` before scanning or for direct caller use.

### Fixed

- Added a separate macOS Intel wheel build that pins `ort` to `2.0.0-rc.10`, which still provides
  prebuilt ONNX Runtime binaries for `x86_64-apple-darwin`.
- Kept macOS arm64, Linux, and Windows wheel builds on `ort` `2.0.0-rc.12`.

## [0.1.0] - 2026-07-24

Initial public release of Patronus Ark.

### Added

- Hybrid Rust/Python security scanning library published as the `patronus-ark` Rust crate and
  Python package.
- `SecurityGateway` for synchronous scans and queued request processing.
- Scan categories for prompt injection, DLP, PII, dynamic PII, sensitive documents, tool
  classification, tool actions, tool tags, routing, and threat detection.
- Layered scanning with native L1 detectors, NTDB L2 model packages, and promoted L3 ONNX
  models.
- Configurable model asset download and cache management.
- Configurable execution gates, L3 scheduling policy, L3 strategy selection, and ONNX backend
  options.
- Hot and persistent result caching.
- Built-in local benchmark runner with packaged benchmark fixtures.
- Rust and Python examples plus documentation for installation, quickstart, configuration,
  assets, result schema, and release/testing workflows.

## Notes

This is the first public changelogged release. Future releases will record Added / Changed /
Deprecated / Removed / Fixed / Security sections here.
