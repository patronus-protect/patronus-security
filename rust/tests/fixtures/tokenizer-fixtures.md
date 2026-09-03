`tokenizer.mmbpe` is a deterministic 1,866-byte test vocabulary in the production
MMBPE v1 binary format. It is deliberately small and contains no trained model.

- BOS=1, EOS=2, unknown=0, metaspace=3.
- Printable ASCII characters 33..126 map to IDs 100+codepoint.
- UTF-8 fallback bytes map to IDs 1000+byte.
- Merge rank 0: metaspace + `a` -> 400; rank 1: `b` + `c` -> 401.
- Added token `<mask>` has ID 99 and consumes preceding whitespace (`lstrip`).

The tests use independent expected IDs and byte spans to check normalization,
merging, UTF-8 fallback, added tokens, piece-cache alignment, bounded encoding,
and L2-to-L3 handoff. The real-artifact parity test compares the production
compact tokenizer to its pinned conversion source without any model inference.

`ntdb_v4.json` is the runtime metadata subset of the pinned `injection_current`
v4 export. It retains the exported 256-content-token declaration so the tests
exercise conversion to the shared 254-content-token runtime budget. Model files
named in the fixture are never loaded by the token-pipeline tests.
