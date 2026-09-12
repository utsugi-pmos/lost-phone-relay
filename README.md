# lost-phone-relay

The meeting point between your lost phone and the panel you look for it from.

**It speaks TLS only, with its own certificate.** No domain or reverse proxy
needed: it generates one the first time, saves it alongside the data and reuses it
for ten years. On startup it prints its SHA-256 fingerprint to the log.

It can be served over plain HTTP with `-no-tls`, and it only makes sense if
there's a reverse proxy in front putting the TLS on. In that mode it warns about
it on startup, because the panel's password and the phone's token would travel
unencrypted.

### If you already have a certificate, use it

First of all: if the domain you're pointing at **already has a certificate** —from
Let's Encrypt or from whoever— hand it over and forget everything else in this
section.

```
-cert /etc/letsencrypt/live/YOURDOMAIN/fullchain.pem \
-key  /etc/letsencrypt/live/YOURDOMAIN/privkey.pem
```

With that the browser warns about nothing, there's no exception to accept and the
phone pins no fingerprint: that certificate is vouched for by its authority. **And
mind you, that's why the relay doesn't announce a fingerprint in that mode** — a
public certificate is renewed every few weeks, and pinning it would break the
phone's connection on every renewal.

With systemd don't put the path bare: the service runs with `DynamicUser` and
can't read a `privkey.pem` that belongs to root. Use `LoadCredential`, which
systemd reads and hands over only to that process —the unit ships the lines in
place and commented—. And add a certbot deploy hook that restarts the service on
renewal: the credentials are read **on startup**, so without it you'd keep serving
the old certificate until it expired.

### Point it at a name, not an IP

Even if it's your root domain with the port — `https://yourdomain.com:8477` — and
you don't need to create any subdomain. A home IP changes, and the day it changes
the phone will stop finding the relay **in silence**, months after you set it up
and without anything warning you.

Changing the address later doesn't force you to re-pair: what the phone pins is
the **certificate**, not the name, so as long as it's the same server it's enough
to correct the address.

### How you trust a certificate nobody signed

Like in SSH: **you pin the one you saw the first time.**

The relay is reached by IP and port, without a domain — which is a legitimate
choice: setting this up shouldn't force you to buy a domain. But then no public
authority can sign anything for it, and accepting any certificate «just because»
would be worse than not encrypting, because it *would seem* secure.

So the phone keeps the fingerprint **during pairing**, which is exactly the moment
when there's already a shared secret —the four-digit code— and from then on it
only accepts that certificate. Whoever gets in the middle afterward presents a
different one and gets rejected; to sneak in they would have had to already be
there during pairing.

Tested, not assumed: with a second relay brought up on the same network and
another certificate, the phone answers

```
el relay presenta OTRO certificado.
  Esperaba 80:CA:2C:...  y llego 0D:4A:31:...  -- no me conecto
```

The only thing forgiven is that **nobody** signed it. An expired certificate, or a
broken one, or one for another name, is still a no — even while pairing.

The browser will warn you the first time and you'll have to accept the exception.
Compare the fingerprint with the one the relay printed on startup. It's ugly and
it's honest: there's no way for a browser to trust a self-signed certificate
without someone saying yes.

## Why it exists

A lost phone is behind CGNAT and asleep. You can't call it. And the laptop you'd
look for it from is behind *its* NAT, so it doesn't work as a destination either.
**Somebody has to have a stable address**, and that's this: a small server that
you host, that the phone connects to *outbound*, and that serves the panel you
open from whatever phone you can borrow.

## Setting it up

The shortest way, a wizard that asks for the port and little else:

```
./install                        on this machine
./install --en usuario@maquina   en otra, por ssh
```

It compiles for that machine's architecture, generates the password, leaves the
systemd service in place and —if you give it a certificate— also the renewal hook.
It doesn't touch your DNS or open ports on your router.

By hand, with Docker:

```
LOST_PHONE_PASSWORD='a long password' docker compose up -d
```

Without Docker:

```
./build
sudo install -Dm755 lost-phone-relay /opt/lost-phone-relay/lost-phone-relay
echo "LOST_PHONE_PASSWORD=a long password" | sudo tee /etc/lost-phone-relay.env
sudo chmod 600 /etc/lost-phone-relay.env
sudo install -Dm644 lost-phone-relay.service /etc/systemd/system/
sudo systemctl enable --now lost-phone-relay
```

`./build` works **even if you don't have Go**: if it doesn't find it, it
compiles with the official image using Docker.

It doesn't start without a password, and it rejects any shorter than **twelve**
characters. A panel with no password is a panel anyone uses to ring, locate and
lock your phone; and a default password would be worse, because it *would seem*
configured.

## Pairing a phone

1. Open the panel, log in, press **Generate code**.
2. Type that code into the phone, under *Find the phone*.

The code is **four digits**, valid for **ten minutes**, **a single time**, and it
dies after three failed attempts.

Four and not ten, and only numbers: this is typed once, on a phone, with the
panel's screen in your other hand. What makes it secure isn't the length, it's the
window: three chances in ten thousand, and only for ten minutes. It's the same
deal a Bluetooth pairing makes.

A comment in `store.go` saves the why, so nobody takes it for an oversight and
"fixes" it by lengthening it.

## The map is drawn by this server

The panel doesn't show coordinates: it shows **a map with a dot**. Some
coordinates aren't an answer when you're out in the street with a borrowed phone in
your hand.

And it's this server that assembles it, not the browser. An `<iframe>` to
openstreetmap was the obvious thing and it was wrong twice: the panel is
`default-src 'none'` on purpose, and opening a hole for a third party in the only
page that can ring, locate and lock your phone is a bad trade; and besides it would
hand your position and the borrowed phone's IP to another party, right when you can
least think about it.

So the relay asks OSM for **nine tiles** and serves a ready-assembled PNG. Nine and
not one: a single one leaves the dot wherever it falls, and half the time that's
two pixels from the edge — useless right when you need to see what's **around** it.
The accuracy circle goes to scale, computed in meters per pixel at that latitude,
and it's omitted when it would come out to a few pixels, where it would be a lie
with the look of detail.

If it can't reach OSM it answers 502 and the panel leaves the usual link. A map
that doesn't load can't take the buttons down with it.

Everything with the standard library: `image/png` and `image/draw`. Zero
dependencies, like the rest.

## The power-off button

The panel can **power the phone off completely**, and it's the only order with no
going back: a powered-off phone doesn't ring, doesn't say where it is and obeys
no one — not you either, from that same panel. To turn it on you have to have it in
your hand.

That's why it carries three locks: only over this channel (which is behind a
password), a permission of its own on the phone that **comes off**, and a button
that makes you type the word `APAGAR` instead of an «accept» that the thumb does on
its own.

## Three decisions that shape the program

**No dependency.** Only the standard library, so `go build` leaves **a static
binary** that runs on the NAS, the VPS or a stranger's Raspberry Pi with no runtime
to install. The whole point of this is that anyone can host it; a five-step setup
means nobody does. The Docker image is `FROM scratch`: no shell, no package
manager, no libc.

**Long wait instead of WebSocket.** The plan said WebSocket. The long wait wins on
everything that matters here: it crosses CGNAT the same, it's the standard library
on both sides, there are no pings to keep up, and **the wait time IS the
heartbeat** the phone already lets you configure. Measured: an order takes **11 ms**
to reach a phone that was waiting.

**The server has no powers.** It forwards orders; whoever decides whether to obey
is the phone, with its own capability matrix. A cracked-open relay **can't do more
than what you had already turned on in the phone**.

## What it stores, and what it doesn't

The last position and **seven days** of history, purged on every write —not with a
timer— so that a relay stopped for a month doesn't wake up with a month of your
movements inside. Nothing more. If someone takes this machine, there's no year of
your life waiting for them.

The state is **a JSON file** under a lock, written to a neighbor and renamed so
that a power cut doesn't leave it half done. It's not a database on purpose: it's a
handful of phones and a few kilobytes. When this needs an index, that will be the
day to bring in SQLite, and not before.

## The two credentials don't mix

| who | with what they get in | what they can do |
|---|---|---|
| the panel | password → session cookie | list, order, pair, remove |

**Failures delay, they don't block, and no one can lock you out.** Each wrong
attempt takes a bit longer to answer, up to three seconds, so guessing in series
stops being worth it. But **the right password always gets in**, whatever failures
come.

This used to be a one-minute block after five failures, and it was a mistake: the
counter is global, so anyone who reached the panel could lock you out by failing
five times a minute — the day you've lost your phone. A protection an attacker can
aim at you is a weapon. That's why the password minimum went up to twelve
characters: if the brake is a delay and not a wall, the length has to do the rest
of the work.
| the phone | token it got on pairing | send its position and pick up its order |

A stolen phone has its token, and with it it **cannot** list your other devices,
un-pair anything or send orders. Which is exactly the case all of this exists for.

## Tests

```
./build && tests/run
```

It brings up a real relay and walks the whole path against it over HTTP. Nothing
is simulated: what fails in a service like this are the seams.

## The API, in case you want another client

From the panel (session cookie):

    POST /api/login      {password}
    GET  /api/devices
    POST /api/pair       {}            -> {codigo, caduca}
    POST /api/command    {id, orden}   sonar|parar|donde|bloquear|desbloquear
    POST /api/forget     {id}

From the phone (`Authorization: Bearer <testigo>`):

    POST /api/device/pair    {codigo, nombre}  -> {id, testigo}
    GET  /api/device/poll                       espera hasta 60 s; 204 si nada
    POST /api/device/report  {posicion}
</content>
