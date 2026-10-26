# Third-party notices

This repository includes two pieces of Microsoft software so that the toolkit runs in a network **without Internet access**. Neither is covered by any license of this repository; each stays under its own terms.

## AaronLocker

| | |
|---|---|
| Location | [`AaronLocker/`](AaronLocker/) |
| Source | <https://github.com/microsoft/AaronLocker>, commit `9d3c943b64f335ffd3c9fa3e6a748ae6f498c5b9` (2022-08-12) |
| Copyright | © Microsoft Corporation |
| License | MIT, see [`AaronLocker/LICENSE`](AaronLocker/LICENSE) |
| Changes | None. The files are unmodified. Local changes live in [`Customizations/`](Customizations/) and are laid over a temporary copy on the reference server at build time. |

## Sysinternals AccessChk

| | |
|---|---|
| Location | [`AaronLocker/AaronLocker/AccessChk.exe`](AaronLocker/AaronLocker/AccessChk.exe) |
| Version | 6.15, 64-bit build (`accesschk64.exe` from <https://download.sysinternals.com/files/AccessChk.zip>, renamed to `AccessChk.exe` as AaronLocker expects) |
| SHA-256 | `843B6B1D275946F2C4569169C10C50EEC0968C4B2F0BED68C50E79F828FAB9F3` (pinned in [`scripts/AL-Settings.psd1`](scripts/AL-Settings.psd1)) |
| Signature | Authenticode, Microsoft Corporation (timestamped) |
| Copyright | © Mark Russinovich, Microsoft Corporation (Sysinternals) |
| License | Sysinternals Software License Terms, <https://learn.microsoft.com/sysinternals/license-terms>. The full text is embedded in the program. |

AccessChk is stored here at the repository owner's direction, for the owner's own offline use. The Sysinternals terms do not allow publishing the software for others to copy. If you are not the repository owner, download AccessChk from Microsoft (link above), check it against the SHA-256, and import it with `scripts\0_AL_get_toolkit.ps1 -AccessChkPath <file>`.
