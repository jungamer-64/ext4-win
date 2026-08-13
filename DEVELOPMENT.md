# Development

The default workspace members are host-independent. On Windows, macOS, or
Linux, run the complete portable gate with:

```console
cargo xtask verify-portable
```

This checks formatting, compiles all portable targets, runs their tests, and
runs Clippy. Plain `cargo test` also selects only the portable default members:
`ext4-core`, `production-reachability`, and `xtask`.

Building and signing the kernel driver remains a Windows-only operation because
it requires MSVC, the Windows Driver Kit, and `cargo-wdk`. On a configured
Windows host, run:

```console
cargo xtask verify-production-driver
```

That command creates one build identity, builds and signs `ext4win.sys`, binds
the LLVM IR, link map, and driver image to that identity, runs the production
reachability gate, and rejects concurrent source changes. It fails explicitly
on macOS and Linux instead of compiling a non-Windows driver shim.
