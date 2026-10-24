# Fuzzing

This independent Cargo workspace uses `libfuzzer-sys` and the parent crate by
path. Keep its pinned `declio` revision synchronized with the parent. CI
compile-checks both targets; it does not run campaigns. The lockfile is tracked;
generated output is ignored.

## Targets

| Target | Maximum input | Work |
| --- | --- | --- |
| `pdb` | 16 MiB | Open MSF; try Info, TPI, IPI, DBI and dependent streams |
| `records` | 64 KiB | Decode the same bytes independently as `TypeRecord`, `IdRecord`, and `SymbolRecord` |

`pdb` tries `/names`, both type hashes, public/global indexes, symbols, section
headers, FPO/frame data, and modules when metadata permits. Optional failures do
not stop other getters. Traversal visits up to 128 modules and 256 records per
collection, including module symbols/C13 subsections; getters still decode entire
requested streams.

`records` expects a little-endian kind followed by payload: **no outer length
prefix or selector byte**. Trailing bytes and decode errors are allowed. See
[LLVM's CodeView guide](https://llvm.org/docs/PDB/CodeViewTypes.html) for framing;
the harness deliberately omits the enclosing stream record length.

Errors are expected; panics are not caught. Oversized inputs are rejected, not
truncated. Input/traversal caps are **not** hard CPU or memory limits: decoders may
allocate from malicious counts before returning. Use process-level isolation and
resource limits.

## Build and run

Prefer Linux or WSL2 with nightly Rust, a C++ compiler, and `cargo-fuzz`:

```sh
rustup toolchain install nightly --profile minimal --no-self-update
cargo install cargo-fuzz --locked
# From the repository root:
cargo check --locked --manifest-path fuzz/Cargo.toml
mkdir -p fuzz/corpus/pdb fuzz/corpus/records fuzz/output
cp tests/corpus/*.pdb fuzz/corpus/pdb/
```

Copy seeds; never point a writable fuzz corpus at checked-in fixtures. Do not
truncate valid PDBs to meet the cap. Seed `records` with kind + payload records,
not whole PDBs or length prefixes; an empty corpus also works.

Bounded Linux/WSL2 campaigns:

```sh
timeout --kill-after=10s 10m cargo +nightly fuzz run pdb -- -max_len=16777216 -timeout=5 -rss_limit_mb=2048 -max_total_time=540
timeout --kill-after=10s 10m cargo +nightly fuzz run records -- -max_len=65536 -timeout=5 -rss_limit_mb=2048 -max_total_time=540
```

`-timeout` limits a case; `-max_total_time` limits the campaign. GNU `timeout`
also bounds build/run time. libFuzzer's RSS limit is monitored, not a hard OS
limit. Limit the entire process tree with a container/cgroup (for example 3 GiB,
including constrained swap) or Windows Job Object; allow compiler/sanitizer
headroom. Virtual-address `ulimit` can conflict with sanitizer shadow memory.
Native Windows support varies; `cargo check` alone is not a fuzz campaign.

Keep generated corpora, artifacts, coverage, build output, and optional
`fuzz/output/` logs local. Check seed provenance/licensing before redistribution.

## Retain regressions

1. Save the target, toolchain, command, limits, and artifact. Reproduce under the
   same limits: `cargo +nightly fuzz run pdb fuzz/artifacts/pdb/crash-<hash>`.
2. Minimize: `cargo +nightly fuzz tmin pdb fuzz/artifacts/pdb/crash-<hash>`.
   Use `records` for record failures and external memory/time limits for both.
   Confirm it is the same failure; use consistent limits for timeout/OOM cases.
3. Fix the parser separately and add a deterministic, provenance-safe regression
   test. Prefer synthetic bytes; retain necessary binaries only in reviewed test
   fixture locations. Keep minimized regressions, not bulk corpora or raw logs.
