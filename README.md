# key-fprint

Show SHA-256 fingerprints for OpenSSH public-key lines without echoing key material or comments. Runs offline and accepts a public-key file or standard input.

## Use

Requires Python 3.8+; no packages to install.

```sh
python key_fprint.py ~/.ssh/id_ed25519.pub
cat public_keys.txt | python key_fprint.py -
```

Input is limited to 1 MiB. Blank lines and `#` comments are skipped. The tool accepts plain OpenSSH public-key lines; `authorized_keys` options are not supported. It checks base64, the encoded key-type field, and that it matches the text label; it does not validate cryptographic parameters or verify ownership. Key comments and blob contents are never printed. A malformed line is reported by line number, and processing continues. Exit status is 0 if all public-key lines are valid, 1 if any line is invalid or no keys are found, and 2 if input cannot be read.

The blob framing follows the SSH `string` encoding in [RFC 4251](https://www.rfc-editor.org/rfc/rfc4251.html). Fingerprints use SHA-256, matching the default fingerprint family documented by [OpenSSH `ssh-keygen`](https://man.openbsd.org/ssh-keygen).

## License

MIT
