# Forensics CTF Pattern Seed

## First pass

- `file`, `exiftool`, `binwalk`, `strings`, `xxd`, `foremost`, `7z l`, `tshark` for pcaps.
- Preserve original artifact; work on copies.
- Extract obvious embedded files before exotic transforms.

## Common lanes

- Stego images: metadata, LSB, palette, alpha channel, zsteg, stegsolve-like channel isolation.
- Audio: spectrogram, waveform, DTMF, SSTV, Morse, hidden files in chunks.
- Archives: appended ZIPs, password hints, known plaintext, zipcrypto/AES cracking.
- PCAP: HTTP objects, DNS exfil, TLS keys, USB HID, FTP/SMTP, stream reconstruction.
- Memory: process list, files, clipboard, browser/session data, volatility profiles.
- PDF/Office: embedded files, macros, object streams, revisions, metadata.

## Repro standard

- Record extraction commands and output paths.
