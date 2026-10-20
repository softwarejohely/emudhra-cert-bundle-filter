# emudhra-cert-bundle-filter

Remove the blocked **eMudhra emSign** and **AAA Certificate Services** root keys from macOS's
`/etc/ssl/cert.pem`, the CA file that the built-in `/usr/bin/curl` trusts.

One zsh script. Run it once by hand, or push it from any MDM that can run a script as root.

> **Unofficial.** Not affiliated with Apple, eMudhra or Homebrew. Test it on one Mac before you roll it out.
> Use at your own risk (see [LICENSE](LICENSE)).

## Why this exists

In October 2026 the private keys of several eMudhra intermediate CAs were reported compromised. Browsers and
other clients that use the macOS system trust store reject them. The advisory says Apple blocked the
intermediates on 19 October, and a `security verify-cert` check on one Mac (macOS 26.7.1) returned
`CSSMERR_TP_CERT_REVOKED` for the test site's chain. But macOS's built-in `curl` does not use the system trust
store. It reads a flat file, `/etc/ssl/cert.pem`, and does not check revocation. As of 20 October 2026 that file
had not been refreshed by Apple (macOS 26.7.1) and still contained the roots, so `curl` (and other tools built on
the system LibreSSL that read the file) still trusted certificates issued under them.

Background: <https://emudhra.we-have-a-problem.com/>, and the report to Mozilla's
[dev-security-policy list](https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/0R3XLJL6FuE/m/0XofdebrAAAJ).

## Check whether a Mac is exposed

```zsh
curl -sS https://dv-g3c-emudhra.we-have-a-problem.com/
```

- `Your client successfully connected to the site. That's bad!` means `curl` still trusts the chain.
- `curl: (60) SSL certificate problem: unable to get local issuer certificate` means it is rejected.

(That test site is run by the people who published the advisory, not by this project.)

## Use

Run once, by hand:

```zsh
sudo zsh filter-cert-bundle.sh
```

From an MDM: upload `filter-cert-bundle.sh` as a custom script, run it as root, and schedule it daily (or at every
check-in). A macOS update restores Apple's file, and the daily run re-applies the filter. Once Apple ships a fixed
file the script finds nothing to remove and does nothing.

Expected output the first time:

```
Found 2 blocked certificate(s) in /etc/ssl/cert.pem (positions 26,44 of 128)
Backup: /etc/ssl/cert.pem.pre-emudhra-filter
VERIFIED: removed 2; /etc/ssl/cert.pem now has 126 certificates, none blocked
```

and on later runs: `No blocked public keys in /etc/ssl/cert.pem (126 certificates). Nothing to do.`

Exit codes: `0` means nothing needed removing, or the filter was applied and verified. `1` means something was wrong
(file missing, a symlink, unparsable, or the new file failed validation), and the original is left untouched.

## What it does

1. Splits `/etc/ssl/cert.pem` into individual certificates and computes each one's public-key hash (SPKI SHA-256).
2. Compares against three blocked hashes copied from the
   [Homebrew `ca-certificates` formula](https://github.com/Homebrew/homebrew-core/blob/main/Formula/c/ca-certificates.rb)
   (`EXCLUDED_SPKI_HASHES`), which excludes AAA Certificate Services and the emSign G3 roots. Matching by key hash
   rather than by name means a renamed or re-encoded copy is still caught. Apple's file contains two of the three
   (`AAA Certificate Services` and `emSign ECC Root CA - G3`).
3. If nothing matches, it exits without touching the file.
4. Otherwise it writes the filtered file next to the original, with Apple's header comments kept, and checks it:
   it must parse, hold exactly the original count minus the removed ones, hold at least 50 certificates, and
   contain no blocked key.
5. It keeps one backup (`/etc/ssl/cert.pem.pre-emudhra-filter`, only the first time), sets `root:wheel` and
   mode `644`, and swaps the new file in with an atomic rename. It then verifies what is on disk.

If any step fails, the original file is not replaced. There is no network access. As root the script always targets
`/etc/ssl/cert.pem`. A `BUNDLE=` override exists only for non-root test runs.

## Undo

```zsh
sudo cp -p /etc/ssl/cert.pem.pre-emudhra-filter /etc/ssl/cert.pem
```

A macOS update also restores Apple's file.

## What was tested

- **macOS 26.7.1 only.** I did not test other versions. If the file cannot be parsed, the script exits `1` and
  changes nothing.
- On a copy of the real file: removed 2 of 128 certificates, a second run did nothing, and garbage, truncated,
  symlinked and missing files all exit `1` and leave the file untouched.
- On a real Mac, after running it: `curl` rejects the eMudhra test site, and normal sites (`apple.com`,
  `github.com`, `google.com`, `amazon.com`, `pypi.org`) still return `200`.

## What it does not cover

- **The macOS keychain** (Safari, most apps). That is Apple's system trust store, and it is a separate layer.
- **Homebrew's CA bundle.** `brew update && brew upgrade ca-certificates` brings in the formula revision that
  excludes the same keys.
- Other bundles: Python (`certifi`), Node, Go, Java, containers and other apps ship their own CA lists.
- **Side effect:** with AAA Certificate Services removed, a site whose chain only reaches that old root will fail
  in the system `curl`. This matches Homebrew's choice, but it is a trade-off.

## License

MIT, see [LICENSE](LICENSE).
