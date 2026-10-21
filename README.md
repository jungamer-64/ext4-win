# ext4-win

`ext4-win` is a native read-write ext4 file-system driver for Windows. It
combines a portable, `no_std` ext4 implementation with a Windows kernel driver
that exposes ext4 volumes through the Windows file-system interface.

The ext4 on-disk format is the external authority. Internal Rust APIs and state
models are free to evolve so that ownership, validation, and durability remain
explicit.

Filesystem semantics belong to the portable core. Windows-specific
representation and lifecycle concerns stay at the driver boundary.

See [DEVELOPMENT.md](DEVELOPMENT.md) for prerequisites, canonical verification
commands, interoperability and release evidence, and live-validation boundaries.
