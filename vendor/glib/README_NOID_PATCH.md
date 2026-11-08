# Noid GLib Safety Backport

Base: the crates.io `glib 0.18.5` source, including its original LICENSE and
COPYRIGHT. Stable Tauri 2 / GTK 3 require the 0.18 API family; a direct upgrade
to the fixed 0.20 family does not satisfy those dependent API/version bounds.
The global Cargo registry source is not modified.

Backport: https://github.com/gtk-rs/gtk-rs-core/pull/1343
Advisory: RUSTSEC-2024-0429 / GHSA-wrw7-89jp-8q8g.

`VariantStrIter::impl_get` must pass a mutable out-pointer to the variadic
`g_variant_get_child` C function. The two upstream-equivalent changes
(`let mut p`, `&mut p`) prevent writes through a shared Rust reference from
being optimized away, followed by a null CStr dereference.
No public API, serialization, GLib ABI, or iterator behavior is changed.

Added regression: `tests/noid_variant_str_iter.rs`, covering forward, reverse,
skipped and exhausted iteration. On a Linux host with GLib development files:

```sh
cargo test --manifest-path vendor/glib/Cargo.toml --release --test noid_variant_str_iter
```

Linux build/release-test verification is pending. Local source is not covered
by registry-only OSV queries; this patch and its test evidence must be reviewed
separately. Remove the fork when stable Tauri supports a fixed GLib family,
or replace it with an official compatible upstream safety release.
