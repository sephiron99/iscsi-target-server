# iSCSI Target Server

A user-space iSCSI target server for Windows 10 and 11, written in Rust.

It exports a memory disk, a raw image file, a Windows volume, or a whole physical
disk (USB flash drives included) as iSCSI disks that an initiator on the same PC
or on another machine can attach.

## Relationship to iSCSIConsole

This project was built with
[TalAloni/iSCSIConsole](https://github.com/TalAloni/iSCSIConsole) as its target:
the goal is a Rust server that covers what iSCSIConsole does and interoperates
with the same initiators.

iSCSIConsole is a reference only. This project contains no code taken or
translated from it. It was written from scratch in Rust against RFC 7143 and the
SCSI standards, with its own structure, and where iSCSIConsole and the standard
disagree it follows the standard. [`difference.md`](difference.md) compares the
two in detail (in Korean).

The main differences:

| Area | iSCSIConsole | This project |
|---|---|---|
| Base standard | RFC 3720 | RFC 7143 |
| Authentication | None | None and one-way CHAP |
| Header/Data digest | Not supported | CRC32C |
| Targets per server | Several | Exactly one, with several LUNs |
| Virtual disk formats | VHD, VMDK | Not supported |
| User interface | Windows Forms GUI | Command-line server with a TOML configuration file |
| Platform | Windows, Mono | Windows 10 and 11 only |

## Status

This is work in progress. Pre-release builds are on the
[releases page](https://github.com/sephiron99/iscsi-target-server/releases);
the project is distributed as a whole and is not published to crates.io.

Verified on real hardware with the Windows iSCSI Initiator on the same PC:

- Discovery, login and logout
- A memory disk and a USB flash drive served as LUN 0 and LUN 1 of one target
- Read-only and read-write access to a whole physical disk
- Taking the physical disk offline while it is served and bringing it back online on exit

Not yet verified:

- Linux open-iscsi and initiators on another machine
- Repartitioning a physical disk through iSCSI while `virtual-disk-identity` is on
- Removing a USB disk while it is being served
- Long-running operation and recovery from abnormal disconnects

Do not use it for data you cannot afford to lose.

## Features

**Protocol**

- Login negotiation, discovery sessions (`SendTargets`) and normal sessions
- One-way CHAP, with the secret kept in a separate file
- CRC32C header and data digests
- Immediate data, unsolicited Data-Out and R2T
- NOP keepalive, logout, Reject, and basic task management responses
- Error recovery level 0 and one connection per session

**SCSI**

- `INQUIRY` with the Supported Pages, Unit Serial Number and Device Identification VPD pages
- `REPORT LUNS`, `TEST UNIT READY`, `REQUEST SENSE`
- `READ CAPACITY (10/16)`, `MODE SENSE (6/10)`
- `READ` and `WRITE (10/12/16)`, `SYNCHRONIZE CACHE (10/16)`
- LUN numbers 0 to 16383, each with its own serial number and device identifier

**Storage backends**

| Backend | Description |
|---|---|
| `memory` | A RAM disk. Empty on every start. |
| `file` | A raw image file. |
| `windows-physical-drive` | A whole physical disk. Requires administrator rights. |
| `windows-volume` | A single volume by drive letter. Requires administrator rights. |

## Building

The server only supports Windows. It builds with the MSVC toolchain, either on
Windows or cross-compiled from WSL. A recent stable Rust toolchain is required.
The default target is `x86_64-pc-windows-msvc`; `i686-pc-windows-msvc` is also
supported.

On Windows:

```sh
cargo build --release -p iscsi-targetd
```

From WSL, the build calls the MSVC linker installed on the Windows side through
the [msvc-wsl-rust](https://github.com/sephiron99/msvc-wsl-rust) scripts. Because
that setup differs per machine, it lives in your own `~/.cargo/config.toml`, not
in this repository. The comments in [`.cargo/config.toml`](.cargo/config.toml)
(in Korean) list the steps and the lines to add. Once that is done:

```sh
cargo build-win64     # 64-bit
cargo build-win32     # 32-bit
```

This produces `target/<target>/release/iscsi-targetd.exe`.

The executable needs no extra DLLs or runtime on Windows 10 and 11. To deploy it,
copy the executable and a configuration file.

## Running

Copy [`sample.toml`](sample.toml) and edit the copy. The sample describes every
option (in Korean) and, unchanged, serves a single 640 MiB memory disk on
`127.0.0.1:3260`.

```
iscsi-targetd.exe --config my.toml --check     validate the configuration and exit
iscsi-targetd.exe --config my.toml             run until Ctrl+C
```

Add `--log-level debug` or `--log-level trace` to see rejected or all SCSI commands.

Then connect with an initiator. On Windows, open `iscsicpl`, add the portal
address and port, and connect to the target.

A minimal configuration:

```toml
version = 1

[listen]
address = "127.0.0.1"
port = 3260

[[targets]]
name = "iqn.2026-10.local.test:disk"

[[targets.luns]]
lun = 0
backend = "memory"
block-size = 512
block-count = 1310720
```

### Serving a physical disk

```toml
[[targets.luns]]
lun = 0
backend = "windows-physical-drive"
device-number = 2
read-only = false
virtual-disk-identity = true
```

- Run the server as administrator. `device-number` is the `Number` column of `Get-Disk`.
- The server takes the disk offline while it is served, so its drive letters
  disappear from the host. It brings the disk back online on a normal exit.
- Set `virtual-disk-identity = true` when the initiator runs on the same PC as the
  server. Otherwise Windows sees the original disk and the iSCSI disk as the same
  disk and takes the iSCSI disk offline. The option shows the initiator a different
  MBR signature, GPT disk GUID and partition GUIDs. The values stored on the disk
  do not change.
- Always disconnect the initiator before stopping the server.

## Limitations

- Windows 10 and 11 are the only supported platforms for the server.
- One target per server. Use several LUNs to export several disks.
- No VHD or VMDK support.
- The GUI only starts and stops the server from a configuration file; it cannot edit
  the configuration or list sessions yet. No Windows service integration.
- Error recovery level 0 only, and one connection per session.
- No session reinstatement. Each TCP connection is its own session.

## Repository layout

The repository is a Cargo workspace with three packages. The two executables do
not depend on each other; both use the library.

| Package | Kind | Contents |
|---|---|---|
| `crates/iscsi-target-server` | Library | Protocol, SCSI, storage backends, configuration, management API, Tokio service |
| `crates/iscsi-targetd` | Executable | Command-line server: arguments, log output, Ctrl+C |
| `crates/iscsi-target-gui` | Executable | Windows GUI. Starts and stops the server from a configuration file and shows its LUNs and log |

By role the library falls into four layers, and upper layers depend on lower ones.

| Layer | Modules |
|---|---|
| Service and configuration | `server`, `config`, `config_file`, `management`, `target_service`, `connection_io` |
| Target protocol state machines | `connection`, `control_state`, `target_login`, `negotiation`, `login_policy`, `auth`, `serial` |
| SCSI and storage | `scsi_target`, `disk_identity`, `platform/windows` |
| Wire format | `lib` (`Pdu`), `frame`, `codec`, `digest`, `bhs`, `opcode`, `login`, `control`, `scsi`, `error` |

Other documents, all in Korean:

- [`AGENTS.md`](AGENTS.md): goals, architecture and working rules
- [`plan.md`](plan.md): remaining work and hardware verification procedures
- [`difference.md`](difference.md): feature comparison with iSCSIConsole

## Testing

```sh
cargo fmt --all -- --check
cargo test-win64
cargo clippy-win64
```

## License

This project is licensed under the GNU General Public License, version 3 or (at
your option) any later version (`GPL-3.0-or-later`). See [`LICENSE`](LICENSE) for
the full text of version 3.

iSCSIConsole, which this project used as a reference, is a separate work under
its own license (LGPL-3.0). No iSCSIConsole code is included here.
