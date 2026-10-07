# Forensics And Stego Recipes

Triage:

```bash
file sample
exiftool sample
binwalk -e sample
strings -a sample | rg -i 'flag|ctf|password|key'
xxd sample | head
```

Images:

- Metadata, comments, thumbnails, appended data.
- LSB by channel/bit-plane, palette tricks, alpha channel, dimensions/crop/hidden layer.
- QR/barcode, OCR, spectrogram, color channel subtraction, difference images.
- Tools: zsteg, stegsolve-like workflows, steghide, stegseek, PIL scripts.

Archives/documents:

- Nested archives, corrupt headers, comments, alternate streams, macros.
- Zip crypto/AES: zip2john/john/hashcat, known plaintext, weak passwords.
- PDFs: embedded files, object streams, JavaScript, comments, image extraction.

PCAPs/logs:

- Follow TCP streams, exported objects, DNS/ICMP exfil, HTTP bodies, TLS keys, credentials.

Memory/disks:

- volatility, strings with offsets, mounted images, deleted files, browser artifacts.
