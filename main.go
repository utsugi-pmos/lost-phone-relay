// SPDX-License-Identifier: GPL-2.0-or-later
//
// lost-phone-relay -- the piece that lets you reach a phone you cannot address.
//
// A lost phone is behind CGNAT and asleep; so is the laptop you would look for
// it from. Neither can be called. Somebody has to have a stable address, and
// this is it: one small server you run yourself, that the phone connects OUT to
// and that serves the panel you open from whatever phone you can borrow.
//
// THREE DECISIONS THAT SHAPE THE WHOLE PROGRAM
//
//  1. NO DEPENDENCIES AT ALL. Standard library only, so `go build` produces one
//     static binary that runs on a stranger's NAS, VPS or Raspberry Pi with no
//     runtime to install and nothing to keep up to date. The whole point is
//     that anybody can host it; a five-step setup means nobody does.
//
//  2. LONG POLLING, NOT WEBSOCKETS. The plan said WebSocket. Long polling wins
//     on every axis that matters here: it traverses CGNAT identically, it is
//     stdlib on both ends (no library on the server, plain QNetworkAccessManager
//     on the phone), there are no pings to keep alive, and the poll timeout IS
//     the configurable heartbeat the phone already exposes. A socket held open
//     for hours would have bought nothing and cost a dependency on both sides.
//
//  3. THE SERVER IS NOT TRUSTED WITH POWERS. It relays orders; the phone checks
//     its own capability matrix before obeying. A relay somebody has broken into
//     cannot do more than the phone was already told it could do.
//
// What it deliberately does NOT do: keep a long history (seven days, purged on
// every write), accept commands from anywhere but an authenticated panel
// session, or hold anything it does not need. If somebody takes this machine,
// there is no year of your movements sitting on it.
package main

import (
	"crypto/tls"
	"flag"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func main() {
	addr := flag.String("addr", envOr("LOST_PHONE_ADDR", ":8080"), "address to listen on")
	dataDir := flag.String("data", envOr("LOST_PHONE_DATA", "./data"), "where to store the state")
	password := flag.String("password", os.Getenv("LOST_PHONE_PASSWORD"), "panel password")
	retention := flag.Int("retention-days", 7, "days of history before it is deleted automatically")
	// -no-tls is the name. -sin-tls was the first one and still works: it is in
	// people's unit files and shell history, and a flag that silently stops
	// being recognised turns into a relay serving TLS where a proxy already
	// does, which fails as a connection refused with nothing explaining it.
	const plainHTTPHelp = "serve over plain HTTP (only if there is a reverse proxy in front that terminates TLS)"
	plainHTTPDefault := envOr("LOST_PHONE_NO_TLS", envOr("LOST_PHONE_SIN_TLS", "")) != ""
	noTLS := flag.Bool("no-tls", plainHTTPDefault, plainHTTPHelp)
	noTLSOld := flag.Bool("sin-tls", false, plainHTTPHelp+" (old name for -no-tls)")
	certFile := flag.String("cert", os.Getenv("LOST_PHONE_CERT"),
		"an existing certificate (e.g. your domain's Let's Encrypt one)")
	keyFile := flag.String("key", os.Getenv("LOST_PHONE_KEY"),
		"the private key of the certificate above")
	flag.Parse()

	if *password == "" {
		// Refusing to start is the only honest option. A panel with no password
		// is a panel anyone on the internet can use to ring, locate and later
		// lock your phone -- and a default password would be worse, because it
		// would look configured.
		log.Fatal("a password is required for the panel: " +
			"-password ... or LOST_PHONE_PASSWORD=...")
	}
	// Twelve, not eight. This password is the only thing between the internet
	// and a button that locks your phone, and the throttle on wrong guesses is
	// a delay rather than a lockout -- deliberately, so nobody can lock the
	// owner out -- which means guessing is slowed, not stopped. The length has
	// to do the rest of the work.
	if len(*password) < 12 {
		log.Fatal("the panel password is too short: minimum 12 characters")
	}

	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		log.Fatalf("cannot create %s: %v", *dataDir, err)
	}

	store, err := openStore(filepath.Join(*dataDir, "state.json"),
		time.Duration(*retention)*24*time.Hour)
	if err != nil {
		log.Fatalf("cannot open the state: %v", err)
	}

	srv := &server{store: store, password: *password}

	mux := http.NewServeMux()
	srv.routes(mux)

	log.Printf("lost-phone-relay listening on %s (data in %s, history %d days)",
		*addr, *dataDir, *retention)

	// Long polling holds a request open for up to a minute, so a write timeout
	// shorter than that would cut the phone off mid-wait. Read timeouts stay
	// short: a client that has not sent its request by then is not one.
	httpSrv := &http.Server{
		Addr:              *addr,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      pollTimeout + 30*time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if *noTLS || *noTLSOld {
		// Only makes sense behind a proxy that terminates TLS. Said at startup so
		// whoever set it by mistake sees it.
		log.Printf("WARNING: serving over PLAIN HTTP. The panel password and the " +
			"phone's token travel unencrypted. Use it only behind a proxy with TLS.")
		log.Fatal(httpSrv.ListenAndServe())
	}

	// If you ALREADY have a real certificate for your domain, use it. It is
	// better in every way: the browser warns about nothing, there is no exception
	// to accept, and the phone does not even need to pin the fingerprint -- pinning
	// exists only because nobody vouches for an unsigned certificate.
	//
	// And mind the renewal: a public certificate changes every few weeks. That is
	// why NO fingerprint is announced in this mode; pinning it would break the
	// phone's connection on every renewal. Trust here is provided by the authority.
	if *certFile != "" || *keyFile != "" {
		if *certFile == "" || *keyFile == "" {
			log.Fatal("-cert and -key go together: one of the two is missing")
		}
		if _, err := tls.LoadX509KeyPair(*certFile, *keyFile); err != nil {
			log.Fatalf("cannot read the certificate (%s) or its key (%s): %v",
				*certFile, *keyFile, err)
		}
		log.Printf("TLS with YOUR certificate: %s", *certFile)
		log.Printf("No fingerprint to pin: its authority vouches for this one, and it changes on renewal.")
		log.Fatal(httpSrv.ListenAndServeTLS(*certFile, *keyFile))
	}

	certPath, keyPath, fingerprint, err := ensureCert(*dataDir)
	if err != nil {
		log.Fatalf("could not prepare the certificate: %v", err)
	}
	log.Printf("TLS with own certificate. SHA-256 fingerprint:")
	log.Printf("  %s", fingerprint)
	log.Printf("The phone keeps this fingerprint when pairing and afterwards only accepts this one.")
	log.Fatal(httpSrv.ListenAndServeTLS(certPath, keyPath))
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}
