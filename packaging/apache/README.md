# Vespid package repository Apache configuration

These files serve `https://packages.vespid.app` from the repository root:

```text
/srv/driftkeep-repo/repos/vespid/public
```

HAProxy terminates TLS on port 443 and forwards to Apache on port 8091.

## Install

```sh
sudo install -m 0644 driftkeep-vespid-http.conf /etc/httpd/conf.d/
sudo install -m 0644 driftkeep-vespid-repo.conf /etc/httpd/conf.d/
sudo httpd -t
sudo systemctl reload httpd
```

The port 80 vhost serves ACME HTTP-01 challenges from `/var/www/acme` and
redirects everything else to HTTPS.

## Certificate

Issue the certificate with the existing acme.sh webroot flow:

```sh
sudo mkdir -p /var/www/acme/.well-known/acme-challenge
sudo /root/.acme.sh/acme.sh --issue --server letsencrypt \
  -d packages.vespid.app -w /var/www/acme --keylength 4096

sudo /root/.acme.sh/acme.sh --install-cert -d packages.vespid.app \
  --key-file       /etc/haproxy/certs/packages.vespid.app.key \
  --fullchain-file /etc/haproxy/certs/packages.vespid.app.crt \
  --reloadcmd 'cat /etc/haproxy/certs/packages.vespid.app.crt \
                    /etc/haproxy/certs/packages.vespid.app.key \
                 > /etc/haproxy/certs/packages.vespid.app.pem && \
               chmod 600 /etc/haproxy/certs/packages.vespid.app.pem && \
               systemctl reload haproxy'
```

HAProxy can serve both names from the same bind by adding the second certificate:

```haproxy
bind *:443 ssl crt /etc/haproxy/certs/packages.driftkeep.app.pem \
                crt /etc/haproxy/certs/packages.vespid.app.pem \
                alpn h2,http/1.1 ssl-min-ver TLSv1.2
```

Reload HAProxy after editing:

```sh
sudo haproxy -c -f /etc/haproxy/haproxy.cfg
sudo systemctl reload haproxy
```

## Publish packages

The signing key stays in root's keyring. Run this in an interactive terminal:

```sh
ssh -t web01
sudo -i
export GPG_TTY=$(tty)

driftkeep-repo gpg export E856432CAC55933A --repo vespid
driftkeep-repo release \
  /home/almalinux/vespid-build/dist/vespid-upload \
  --repo vespid
```

`release` signs the RPMs and repository metadata with the Vespid key and
publishes the trees under `/srv/driftkeep-repo/repos/vespid/public`.

## Verify

```sh
curl -I https://packages.vespid.app/
curl -fsSL https://packages.vespid.app/keys/vespid-packages.asc | head
curl -fsSI https://packages.vespid.app/rpm/x86_64/repodata/repomd.xml
curl -fsSI https://packages.vespid.app/deb/dists/stable/InRelease
```
