// SPDX-License-Identifier: GPL-2.0-or-later
//
// The state, in one JSON file under a mutex.
//
// Not a database, on purpose. What this holds is a handful of devices, one
// pending command each and a week of positions -- kilobytes, not gigabytes. A
// JSON file rewritten atomically has no schema migrations, no driver, no cgo
// and nothing to back up but a file you can read with your eyes. If this ever
// needs an index, that is the day it needs SQLite, and not before.

package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Four digits, and nothing else. This is typed ONCE, on a phone, with the
// numeric keypad. Ten alphanumeric characters were indefensible: whoever was
// pairing had the phone in one hand and the screen in the other.
//
// What makes this safe is not the length, it is that it expires in ten minutes
// and dies on the third failed attempt: 3 chances in 10,000, and only within
// that window. It is the same deal a Bluetooth pairing makes.
const pairAlphabet = "0123456789"

// The alphabet of phone IDENTIFIERS, which nobody types.
const idAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"

const (
	pairCodeLength = 4
	pairCodeLife   = 10 * time.Minute
	pairMaxTries   = 3
)

type Position struct {
	When           time.Time `json:"when"`
	HasCoordinates bool      `json:"has_coordinates"`
	Latitude       float64   `json:"latitude"`
	Longitude      float64   `json:"longitude"`
	AccuracyMeters int       `json:"accuracy_m"`
	Source         string    `json:"source"`
	Cell           string    `json:"cell,omitempty"`
	Wifi           string    `json:"wifi,omitempty"`
	BatteryPercent int       `json:"battery"`
}

type Device struct {
	ID       string    `json:"id"`
	Name     string    `json:"name"`
	Token    string    `json:"token"`
	Added    time.Time `json:"added"`
	LastSeen time.Time `json:"last_seen"`
	// Exactly one pending command. A queue would let a panel that somebody
	// leant on deliver six alarms in a row to a phone that just came back
	// online; the last order is the one that means anything.
	Pending string     `json:"pending,omitempty"`
	History []Position `json:"history"`
}

type pairing struct {
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
	Tries   int       `json:"tries"`
}

type state struct {
	Devices []*Device `json:"devices"`
	Pair    *pairing  `json:"pairing,omitempty"`
}

type store struct {
	mu        sync.Mutex
	path      string
	retention time.Duration
	st        state

	// One channel per device, closed when a command lands, so a long poll wakes
	// the instant an order arrives instead of at the end of its wait.
	waiters map[string]chan struct{}
}

var errNotFound = errors.New("does not exist")

func openStore(path string, retention time.Duration) (*store, error) {
	s := &store{path: path, retention: retention, waiters: map[string]chan struct{}{}}
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		// The file was called estado.json until 2026-09-11. Reading the old name
		// when the new one is missing is what keeps a relay that has been running
		// for weeks from waking up with no phones registered -- which is exactly
		// what happened on the first deploy of this change, caught because the
		// device list came back empty. The next save writes the new name.
		legacy := filepath.Join(filepath.Dir(path), "estado.json")
		if d2, err2 := os.ReadFile(legacy); err2 == nil {
			log.Printf("reading the state from %s (the old name); it will be saved as %s",
				legacy, filepath.Base(path))
			data, err = d2, nil
		}
	}
	if err == nil {
		// decodeWithLegacyKeys, not json.Unmarshal: a state file written before
		// 2026-09-11 carries the Spanish keys and losing it would lose the
		// registered phones. See legacy.go.
		if err := decodeWithLegacyKeys(data, &s.st); err != nil {
			return nil, err
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	return s, nil
}

// Always called with the lock held.
func (s *store) save() error {
	// Written to a neighbour and renamed: a power cut halfway through a write
	// would otherwise leave a truncated file, and the next start would come up
	// with no devices paired at all.
	tmp := s.path + ".tmp"
	data, err := json.MarshalIndent(&s.st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func randomString(n int, alphabet string) (string, error) {
	out := make([]byte, n)
	max := big.NewInt(int64(len(alphabet)))
	for i := range out {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		out[i] = alphabet[v.Int64()]
	}
	return string(out), nil
}

func randomToken() (string, error) {
	return randomString(43, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
}

// --- pairing ----------------------------------------------------------------

func (s *store) startPairing() (string, time.Time, error) {
	code, err := randomString(pairCodeLength, pairAlphabet)
	if err != nil {
		return "", time.Time{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.st.Pair = &pairing{Code: code, Expires: time.Now().Add(pairCodeLife)}
	return code, s.st.Pair.Expires, s.save()
}

// claimPairing turns a code into a device and its token. The code dies on use,
// on expiry, or after three wrong guesses -- which is what makes ten characters
// enough: there is nothing to grind against.
func (s *store) claimPairing(code, name string) (*Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p := s.st.Pair
	if p == nil {
		return nil, errors.New("no pairing is open")
	}
	if time.Now().After(p.Expires) {
		s.st.Pair = nil
		_ = s.save()
		return nil, errors.New("the code has expired")
	}
	// Constant time, so the answer cannot be found one character at a time by
	// timing the reply.
	if subtle.ConstantTimeCompare([]byte(code), []byte(p.Code)) != 1 {
		p.Tries++
		if p.Tries >= pairMaxTries {
			s.st.Pair = nil
		}
		_ = s.save()
		return nil, errors.New("wrong code")
	}

	id, err := randomString(12, idAlphabet)
	if err != nil {
		return nil, err
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	if name == "" {
		name = "phone"
	}
	// A pairing with the same name as another that NEVER said where it was takes
	// the old one down with it. That record is not another phone: it is an attempt
	// that was left half-done -- the code was mistyped, the network dropped, the
	// package was reinstalled -- and leaving it there does real harm. Two identical
	// cards show up in the panel, and half the time you tap "Sonar" on the dead
	// one: the order is queued for a device that will never poll again, and what
	// you see is a button that does not work.
	//
	// Only those that never reported a position are deleted. One that did was a
	// real phone at some point, and that one is not touched even if it shares a name.
	alive := s.st.Devices[:0]
	for _, d := range s.st.Devices {
		if d.Name == name && len(d.History) == 0 {
			log.Printf("pairing: removing a previous %q that never said where it was (%s)", d.Name, d.ID)
			continue
		}
		alive = append(alive, d)
	}
	s.st.Devices = alive

	dev := &Device{ID: id, Name: name, Token: token, Added: time.Now(), LastSeen: time.Now()}
	s.st.Devices = append(s.st.Devices, dev)
	s.st.Pair = nil
	return dev, s.save()
}

// --- devices ----------------------------------------------------------------

func (s *store) byToken(token string) *Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.st.Devices {
		if subtle.ConstantTimeCompare([]byte(d.Token), []byte(token)) == 1 {
			return d
		}
	}
	return nil
}

func (s *store) list() []*Device {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Device, len(s.st.Devices))
	copy(out, s.st.Devices)
	return out
}

func (s *store) forget(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, d := range s.st.Devices {
		if d.ID == id {
			s.st.Devices = append(s.st.Devices[:i], s.st.Devices[i+1:]...)
			return s.save()
		}
	}
	return errNotFound
}

func (s *store) seen(token string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.st.Devices {
		if d.Token == token {
			d.LastSeen = time.Now()
			_ = s.save()
			return
		}
	}
}

// --- commands ---------------------------------------------------------------

func (s *store) queue(id, command string) error {
	s.mu.Lock()
	for _, d := range s.st.Devices {
		if d.ID == id {
			d.Pending = command
			if err := s.save(); err != nil {
				s.mu.Unlock()
				return err
			}
			// Wake whoever is waiting, then drop the channel so the next poll
			// gets a fresh one.
			if ch, ok := s.waiters[id]; ok {
				close(ch)
				delete(s.waiters, id)
			}
			s.mu.Unlock()
			return nil
		}
	}
	s.mu.Unlock()
	return errNotFound
}

// takePending returns the pending command and clears it in one step, so an
// order can never be delivered twice.
func (s *store) takePending(id string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.st.Devices {
		if d.ID == id {
			cmd := d.Pending
			if cmd != "" {
				d.Pending = ""
				_ = s.save()
			}
			return cmd
		}
	}
	return ""
}

func (s *store) wait(id string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, ok := s.waiters[id]; ok {
		return ch
	}
	ch := make(chan struct{})
	s.waiters[id] = ch
	return ch
}

// --- history ----------------------------------------------------------------

func (s *store) record(id string, p Position) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.st.Devices {
		if d.ID == id {
			d.LastSeen = time.Now()
			d.History = append(d.History, p)
			// Purged on every write rather than by a timer: a relay that has
			// been idle for a month must not be holding a month of positions
			// the moment it wakes up.
			cutoff := time.Now().Add(-s.retention)
			kept := d.History[:0]
			for _, old := range d.History {
				if old.When.After(cutoff) {
					kept = append(kept, old)
				}
			}
			d.History = kept
			return s.save()
		}
	}
	return errNotFound
}
