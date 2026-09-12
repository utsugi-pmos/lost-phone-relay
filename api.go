// SPDX-License-Identifier: GPL-2.0-or-later
//
// The HTTP surface: two audiences with two different kinds of credential.
//
//   the panel   a browser, a password, a session cookie
//   the phone   a device token it got when it was paired, in a header
//
// They are kept apart on purpose. A phone token can report a position and pick
// up an order; it cannot list your other devices, unpair anything or issue
// commands. So a stolen phone -- the case this whole program exists for -- is
// not a way into everything else you own.

package main

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// How long a phone's poll is held open before answering "nothing". This IS the
// heartbeat: the phone reconnects immediately afterwards, so an order is picked
// up within a second of being issued, and the cost is one idle TCP connection.
const pollTimeout = 60 * time.Second

type server struct {
	store    *store
	password string

	mu       sync.Mutex
	sessions map[string]time.Time

	// Wrong passwords are counted globally rather than per address: whoever is
	// guessing controls their own source address, so per-address counting is a
	// lock that opens itself.
	failures int
}

func (s *server) routes(mux *http.ServeMux) {
	mux.HandleFunc("/", s.handlePanel)

	// panel
	mux.HandleFunc("/api/login", s.handleLogin)
	mux.HandleFunc("/api/logout", s.panelOnly(s.handleLogout))
	mux.HandleFunc("/api/devices", s.panelOnly(s.handleDevices))
	mux.HandleFunc("/api/pair", s.panelOnly(s.handlePair))
	mux.HandleFunc("/api/command", s.panelOnly(s.handleCommand))
	mux.HandleFunc("/api/forget", s.panelOnly(s.handleForget))
	// Behind the panel session on purpose: otherwise it would be a tile proxy
	// open to the internet with the bandwidth of whoever hosts it.
	mux.HandleFunc("/api/map", s.panelOnly(s.handleMap))

	// phone
	mux.HandleFunc("/api/device/pair", s.handleDevicePair)
	mux.HandleFunc("/api/device/poll", s.deviceOnly(s.handlePoll))
	mux.HandleFunc("/api/device/report", s.deviceOnly(s.handleReport))
}

// --- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v any) error {
	// Capped: an unbounded body on an endpoint that anyone can reach is a way
	// to fill the memory of a machine that is meant to sit quiet for months.
	data, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, 64*1024))
	if err != nil {
		return err
	}
	// A phone still on lost-phone 1.1 posts the Spanish keys. See legacy.go.
	return decodeWithLegacyKeys(data, v)
}

// --- panel authentication ---------------------------------------------------

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return
	}

	// A DELAY on the wrong answer, never a lockout.
	//
	// This used to lock the panel for a minute after five failures, and that was
	// a mistake worth spelling out: the counter was global, so ANYBODY who could
	// reach the panel could keep the owner out of it by failing five times a
	// minute -- on precisely the day they had lost their phone. A protection
	// that an attacker can aim at you is a weapon.
	//
	// The delay has the property the lockout did not: the right password always
	// works, immediately, however many wrong ones came before it. Guessing gets
	// slower and slower; being the owner does not.
	s.mu.Lock()
	failures := s.failures
	s.mu.Unlock()

	if !constantTimeEqual(body.Password, s.password) {
		// Up to three seconds, growing. Sequential guessing collapses; a
		// parallel attacker still pays it on every connection.
		wait := time.Duration(failures) * 300 * time.Millisecond
		if wait > 3*time.Second {
			wait = 3 * time.Second
		}
		time.Sleep(wait)

		s.mu.Lock()
		s.failures++
		s.mu.Unlock()
		log.Printf("panel: wrong password from %s (attempt %d)", r.RemoteAddr, failures+1)
		writeError(w, http.StatusUnauthorized, "wrong password")
		return
	}

	s.mu.Lock()
	s.failures = 0
	// Expired sessions are only ever noticed when their own cookie comes back,
	// so without this sweep the map grows for the life of the process. Login is
	// the right moment: it is the only thing that adds to it, and it is rare.
	for token, expiry := range s.sessions {
		if time.Now().After(expiry) {
			delete(s.sessions, token)
		}
	}
	s.mu.Unlock()

	token, err := randomToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not create the session")
		return
	}
	s.mu.Lock()
	if s.sessions == nil {
		s.sessions = map[string]time.Time{}
	}
	s.sessions[token] = time.Now().Add(12 * time.Hour)
	s.mu.Unlock()

	http.SetCookie(w, &http.Cookie{
		Name:     "lost_phone_sesion",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// Secure is NOT forced: plenty of people will run this behind a reverse
		// proxy on a LAN name with no certificate, and a cookie the browser
		// refuses to send is a panel that cannot log in at all. Put it behind
		// TLS -- the README says so in the first paragraph.
		MaxAge: 12 * 60 * 60,
	})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("lost_phone_sesion"); err == nil {
		s.mu.Lock()
		delete(s.sessions, c.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "lost_phone_sesion", Value: "", Path: "/", MaxAge: -1})
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) panelOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("lost_phone_sesion")
		if err != nil {
			writeError(w, http.StatusUnauthorized, "you must log in")
			return
		}
		s.mu.Lock()
		expiry, ok := s.sessions[c.Value]
		if ok && time.Now().After(expiry) {
			delete(s.sessions, c.Value)
			ok = false
		}
		s.mu.Unlock()
		if !ok {
			writeError(w, http.StatusUnauthorized, "the session has expired")
			return
		}
		next(w, r)
	}
}

// --- panel endpoints --------------------------------------------------------

type deviceView struct {
	ID       string     `json:"id"`
	Name     string     `json:"name"`
	LastSeen time.Time  `json:"last_seen"`
	Online   bool       `json:"online"`
	Pending  string     `json:"pending,omitempty"`
	Last     *Position  `json:"last,omitempty"`
	History  []Position `json:"history"`
}

func (s *server) handleDevices(w http.ResponseWriter, r *http.Request) {
	devices := s.store.list()
	out := make([]deviceView, 0, len(devices))
	for _, d := range devices {
		v := deviceView{
			ID: d.ID, Name: d.Name, LastSeen: d.LastSeen, Pending: d.Pending,
			// "Connected" means it polled within two heartbeats. One would call
			// a phone lost every time a poll landed a second late.
			Online:  time.Since(d.LastSeen) < 2*pollTimeout,
			History: d.History,
		}
		if n := len(d.History); n > 0 {
			v.Last = &d.History[n-1]
		}
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *server) handlePair(w http.ResponseWriter, r *http.Request) {
	code, expires, err := s.store.startPairing()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"code": code, "expires": expires})
}

// The verbs the relay will forward. English, with the Spanish ones the phone
// answered to first: the daemon takes both (daemon/main.cpp), and a panel or a
// script written against the old names must keep working.
var allowedCommands = map[string]bool{
	"ring": true, "stop": true, "where": true, "lock": true, "unlock": true,
	"sonar": true, "parar": true, "donde": true, "bloquear": true, "desbloquear": true,
	// Power the whole phone off. The relay only forwards it; who decides whether
	// to obey is the phone, which ships it disabled and only accepts it over this
	// channel.
	"off": true, "apagar": true,
}

// The answer to a phone's poll carries the command under BOTH keys: "command"
// is the name from 2026-09-11 on, and "orden" is what a phone still running
// lost-phone 1.1 reads. It costs one short string and it means the relay can be
// deployed before the phones are upgraded, which is the only order that does not
// leave a phone deaf to its own alarm.
func pollAnswer(cmd string) map[string]string {
	return map[string]string{"command": cmd, "orden": cmd}
}

func (s *server) handleCommand(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID      string `json:"id"`
		Command string `json:"command"`
		// Only "bloquear" carries one: the text a stranger reads on the lock
		// screen. It is the whole point of a remote lock -- a locked phone with
		// no way to reach you is a brick, not a lost phone.
		Message string `json:"message"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	// Allow-listed here as well as checked on the phone. The phone's capability
	// matrix is the real control; this only stops the relay from forwarding
	// something nobody has ever implemented.
	if !allowedCommands[body.Command] {
		writeError(w, http.StatusBadRequest, "unknown command")
		return
	}

	command := body.Command
	if (body.Command == "lock" || body.Command == "bloquear") && body.Message != "" {
		// Newlines would split the order in two on the phone, where the first
		// word is the verb and the rest is the argument. One line, always.
		clean := strings.Join(strings.Fields(body.Message), " ")
		if len(clean) > 200 {
			clean = clean[:200]
		}
		command = body.Command + " " + clean
	}

	if err := s.store.queue(body.ID, command); err != nil {
		writeError(w, http.StatusNotFound, "that phone is not here")
		return
	}
	log.Printf("panel: command '%s' for %s", body.Command, body.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *server) handleForget(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID string `json:"id"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	if err := s.store.forget(body.ID); err != nil {
		writeError(w, http.StatusNotFound, "that phone is not here")
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

// --- phone endpoints --------------------------------------------------------

func (s *server) handleDevicePair(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Code string `json:"code"`
		Name string `json:"name"`
	}
	if err := readJSON(r, &body); err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	dev, err := s.store.claimPairing(strings.TrimSpace(strings.ToLower(body.Code)), body.Name)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	log.Printf("paired a new phone: %s (%s)", dev.Name, dev.ID)
	writeJSON(w, http.StatusOK, map[string]string{"id": dev.ID, "token": dev.Token})
}

type deviceRequest struct {
	*http.Request
	device *Device
}

func (s *server) deviceOnly(next func(http.ResponseWriter, deviceRequest)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			writeError(w, http.StatusUnauthorized, "missing token")
			return
		}
		dev := s.store.byToken(token)
		if dev == nil {
			writeError(w, http.StatusUnauthorized, "unknown token")
			return
		}
		next(w, deviceRequest{Request: r, device: dev})
	}
}

func (s *server) handlePoll(w http.ResponseWriter, r deviceRequest) {
	id := r.device.ID
	s.store.seen(r.device.Token)

	// Take whatever is already waiting before blocking: an order issued while
	// the phone was offline has to be delivered the moment it comes back, not
	// on the poll after that.
	if cmd := s.store.takePending(id); cmd != "" {
		writeJSON(w, http.StatusOK, pollAnswer(cmd))
		return
	}

	wake := s.store.wait(id)
	select {
	case <-wake:
		cmd := s.store.takePending(id)
		if cmd == "" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		writeJSON(w, http.StatusOK, pollAnswer(cmd))
	case <-time.After(pollTimeout):
		w.WriteHeader(http.StatusNoContent)
	case <-r.Context().Done():
		// The phone hung up: the network moved, it suspended, the battery went.
		// Nothing to do, and nothing to log -- it is the normal case.
	}
}

func (s *server) handleReport(w http.ResponseWriter, r deviceRequest) {
	var p Position
	if err := readJSON(r.Request, &p); err != nil {
		writeError(w, http.StatusBadRequest, "unreadable body")
		return
	}
	if p.When.IsZero() {
		p.When = time.Now()
	}
	if err := s.store.record(r.device.ID, p); err != nil && !errors.Is(err, errNotFound) {
		writeError(w, http.StatusInternalServerError, "could not save it")
		return
	}
	// Logged. Today it took an hour to work out why the map was not updating,
	// and part of that hour was that here there was no way to tell whether the
	// reports were even arriving: the panel said "connected" -- that is the poll
	// -- and the position stayed the same as before. One line per report settles
	// the question of "is it the phone or is it me".
	if p.HasCoordinates {
		log.Printf("phone %s: position %.5f,%.5f (+-%dm, %s) battery %d%%",
			r.device.ID, p.Latitude, p.Longitude, p.AccuracyMeters, p.Source, p.BatteryPercent)
	} else {
		log.Printf("phone %s: report without coordinates (%s) battery %d%%",
			r.device.ID, p.Source, p.BatteryPercent)
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
