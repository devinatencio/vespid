# RPM Signing

Vespid RPM packages can be signed with a GPG key so package managers
(`dnf`, `zypper`, `yum`) do not warn about an untrusted origin.

## One-Time Setup

### 1. Create a GPG signing key

```bash
gpg --gen-key
```

Use the default (RSA + RSA, 3072 bits, no expiry). Suggested user ID:

```
Real name:  Vespid Security
Email:      team@vespid.dev
```

Protect the key with a passphrase and back up the key material:

```bash
gpg --export --armor "Vespid Security" > vespid-public.gpg
gpg --export-secret-keys --armor "Vespid Security" > vespid-private.gpg
```

### 2. Configure RPM to use the key

```bash
echo '%_gpg_name Vespid Security' >> ~/.rpmmacros
```

### 3. Import the public key on systems that will install the RPM

```bash
rpm --import vespid-public.gpg
```

Or host it on your server and users can import it:

```bash
curl -fsSL https://vespid.dev/gpg.asc | sudo rpm --import -
```

## Signing

### Via make (recommended)

Build and sign in one step:

```bash
make rpm SIGN_KEY="Vespid Security"
```

Or sign already-built RPMs:

```bash
make sign-rpms SIGN_KEY="Vespid Security"
```

### Via the signing script

```bash
./packaging/sign-rpms.sh "Vespid Security"
```

Both approaches sign all `.rpm` files under `rpmbuild/RPMS/`
and `rpmbuild/SRPMS/`.

### Passphrase handling

If the GPG key has a passphrase, `rpm --addsign` will prompt for it.
To avoid interactive prompts during automation, configure `gpg-agent`:

```bash
# Start gpg-agent and cache the passphrase
gpg --detach-sign /dev/null
```

Or run `gpg-agent` with a long cache TTL:

```bash
echo "default-cache-ttl 86400" >> ~/.gnupg/gpg-agent.conf
gpg-connect-agent reloadagent /bye
```

## Verification

Check that an RPM is properly signed:

```bash
rpm -Kv rpmbuild/RPMS/noarch/vespid-1.0.0-1.el9.noarch.rpm
```

Look for `OK` next to each signature line:

```
    Header V4 RSA/SHA256 Signature, key ID ABCDEF12: OK
    Header SHA256 digest: OK
    Payload SHA256 digest: OK
    V4 RSA/SHA256 Signature, key ID ABCDEF12: OK
    MD5 digest: OK
```

For end-users, verification against the public key:

```bash
rpm --import vespid-public.gpg
rpm -K vespid-1.0.0-1.el9.noarch.rpm
# Output: digests SIGNATURES OK
```

## CI / Automation

For automated builds (e.g. GitHub Actions), avoid interactive passphrase
prompts by using an unprotected subkey or a dedicated signing key without
a passphrase stored on the build runner. See also `rpmsign(8)` for
`--fskpassword` / `--with-file` options.
