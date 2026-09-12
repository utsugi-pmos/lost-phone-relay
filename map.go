// SPDX-License-Identifier: GPL-2.0-or-later
//
// The map you actually look at when the phone is gone.
//
// Coordinates are not an answer. "37.56620, -1.30361" tells you nothing while
// you are standing in the street with somebody else's phone in your hand; a
// picture with a dot on it tells you everything in one glance. That is the
// whole reason this file exists.
//
// WHY THE SERVER FETCHES THE TILES INSTEAD OF THE BROWSER
//
// The obvious build is an <iframe> to openstreetmap.org, and it was rejected
// twice over:
//
//  1. The panel's CSP is "default-src 'none'" on purpose -- it loads nothing
//     from anywhere. Opening a hole for a third party in the one page that can
//     ring, locate and lock your phone is a bad trade for a convenience.
//
//  2. It would hand your position AND the borrowed phone's IP to somebody else,
//     at the exact moment you are least able to think about it. The rest of
//     this project already refuses that: the README says Wi-Fi lookup belongs
//     to the relay "so that the phone never talks to a third party". A map is
//     the same problem and gets the same answer.
//
// So YOUR server fetches the tiles and serves one finished PNG. The device you
// borrowed talks only to you. OSM sees your server asking for nine tiles, which
// is what it would have seen anyway, and nothing about who is looking.
//
// Nine tiles, not one: a single tile puts the phone wherever it happens to fall,
// and half the time that is two pixels from the edge, which is useless exactly
// when you need to see what is AROUND the dot.
package main

import (
	"context"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"math"
	"net/http"
	"strconv"
	"sync"
	"time"
)

const (
	tileSize  = 256
	tileGrid  = 3 // 3x3 tiles around the phone -> 768x768
	tileHost  = "https://tile.openstreetmap.org"
	mapTimeout = 8 * time.Second

	// Asked of OSM by their tile usage policy: a real contact, so that a
	// self-hosted relay behaving badly can be told rather than just blocked.
	tileAgent = "lost-phone-relay/1.0 (self-hosted; https://github.com/utsugi-pmos/lost-phone)"
)

// tileFloat turns degrees into fractional tile coordinates (Web Mercator).
// The fraction is the whole point: it is what puts the dot on the right doorway
// instead of the right neighbourhood.
func tileFloat(lat, lon float64, z int) (float64, float64) {
	n := math.Exp2(float64(z))
	x := (lon + 180.0) / 360.0 * n
	latRad := lat * math.Pi / 180.0
	y := (1.0 - math.Log(math.Tan(latRad)+1.0/math.Cos(latRad))/math.Pi) / 2.0 * n
	return x, y
}

// metersPerPixel at this latitude and zoom, so the accuracy ring is drawn to
// scale instead of being a decorative circle.
func metersPerPixel(lat float64, z int) float64 {
	return 156543.03392 * math.Cos(lat*math.Pi/180.0) / math.Exp2(float64(z))
}

func (s *server) handleMap(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	lat, err1 := strconv.ParseFloat(q.Get("lat"), 64)
	lon, err2 := strconv.ParseFloat(q.Get("lon"), 64)
	if err1 != nil || err2 != nil || lat < -85 || lat > 85 || lon < -180 || lon > 180 {
		http.Error(w, "coordinates invalid", http.StatusBadRequest)
		return
	}
	z := 16
	if v, err := strconv.Atoi(q.Get("z")); err == nil {
		z = v
	}
	if z < 3 {
		z = 3
	}
	if z > 18 {
		z = 18
	}
	precision := 0.0
	if v, err := strconv.ParseFloat(q.Get("precision"), 64); err == nil && v > 0 {
		precision = v
	}

	ctx, cancel := context.WithTimeout(r.Context(), mapTimeout)
	defer cancel()

	img, ok := s.render(ctx, lat, lon, z, precision)
	if !ok {
		// Every tile failed: no internet on the relay, or OSM is unreachable.
		// Saying so plainly beats serving a blank square that looks like the
		// phone is in the middle of nowhere.
		http.Error(w, "could not fetch the map", http.StatusBadGateway)
		return
	}

	// Short cache: the position barely moves between two refreshes of the
	// panel, and re-fetching nine tiles every ten seconds would be rude to OSM
	// and slow for whoever is looking.
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "private, max-age=60")
	_ = png.Encode(w, img)
}

func (s *server) render(ctx context.Context, lat, lon float64, z int, precision float64) (image.Image, bool) {
	fx, fy := tileFloat(lat, lon, z)
	cx, cy := int(fx), int(fy)
	half := tileGrid / 2

	side := tileGrid * tileSize
	canvas := image.NewRGBA(image.Rect(0, 0, side, side))
	// A neutral ground, so a tile that fails to arrive reads as "missing" and
	// not as "empty land".
	draw.Draw(canvas, canvas.Bounds(), &image.Uniform{color.RGBA{0xe8, 0xe6, 0xe1, 0xff}},
		image.Point{}, draw.Src)

	var wg sync.WaitGroup
	var mu sync.Mutex
	got := 0
	for dy := -half; dy <= half; dy++ {
		for dx := -half; dx <= half; dx++ {
			wg.Add(1)
			go func(dx, dy int) {
				defer wg.Done()
				tile := s.fetchTile(ctx, z, cx+dx, cy+dy)
				if tile == nil {
					return
				}
				at := image.Rect((dx+half)*tileSize, (dy+half)*tileSize,
					(dx+half+1)*tileSize, (dy+half+1)*tileSize)
				mu.Lock()
				draw.Draw(canvas, at, tile, image.Point{}, draw.Src)
				got++
				mu.Unlock()
			}(dx, dy)
		}
	}
	wg.Wait()
	if got == 0 {
		return nil, false
	}

	// Where the phone is, in canvas pixels.
	px := (fx - float64(cx-half)) * tileSize
	py := (fy - float64(cy-half)) * tileSize

	if precision > 0 {
		ring := precision / metersPerPixel(lat, z)
		// Below a few pixels the ring is a lie dressed as detail, and above the
		// canvas it says nothing either.
		if ring >= 4 && ring <= float64(side) {
			fillCircle(canvas, px, py, ring, color.RGBA{0x2d, 0x6c, 0xdf, 0x28})
			strokeCircle(canvas, px, py, ring, color.RGBA{0x2d, 0x6c, 0xdf, 0x99})
		}
	}
	// The dot itself, with a white ring so it survives a dark map.
	fillCircle(canvas, px, py, 9, color.RGBA{0xff, 0xff, 0xff, 0xff})
	fillCircle(canvas, px, py, 6, color.RGBA{0xc0, 0x39, 0x2b, 0xff})
	return canvas, true
}

func (s *server) fetchTile(ctx context.Context, z, x, y int) image.Image {
	n := 1 << z
	if y < 0 || y >= n {
		return nil // off the top or bottom of the world
	}
	x = ((x % n) + n) % n // wrap around the date line

	url := tileHost + "/" + strconv.Itoa(z) + "/" + strconv.Itoa(x) + "/" + strconv.Itoa(y) + ".png"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", tileAgent)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	img, err := png.Decode(resp.Body)
	if err != nil {
		return nil
	}
	return img
}

// Two tiny drawing helpers, because pulling in a graphics library to paint a
// dot would cost this program the one property that lets anybody host it: it
// builds anywhere, with nothing installed.

func fillCircle(dst *image.RGBA, cx, cy, r float64, c color.RGBA) {
	r2 := r * r
	for y := int(cy - r); y <= int(cy+r); y++ {
		for x := int(cx - r); x <= int(cx+r); x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			if dx*dx+dy*dy <= r2 {
				blend(dst, x, y, c)
			}
		}
	}
}

func strokeCircle(dst *image.RGBA, cx, cy, r float64, c color.RGBA) {
	inner := (r - 1.5) * (r - 1.5)
	outer := (r + 1.5) * (r + 1.5)
	for y := int(cy - r - 2); y <= int(cy+r+2); y++ {
		for x := int(cx - r - 2); x <= int(cx+r+2); x++ {
			dx, dy := float64(x)-cx, float64(y)-cy
			d := dx*dx + dy*dy
			if d >= inner && d <= outer {
				blend(dst, x, y, c)
			}
		}
	}
}

func blend(dst *image.RGBA, x, y int, c color.RGBA) {
	if !(image.Point{x, y}).In(dst.Bounds()) {
		return
	}
	if c.A == 0xff {
		dst.SetRGBA(x, y, c)
		return
	}
	old := dst.RGBAAt(x, y)
	a := float64(c.A) / 255.0
	dst.SetRGBA(x, y, color.RGBA{
		R: uint8(float64(c.R)*a + float64(old.R)*(1-a)),
		G: uint8(float64(c.G)*a + float64(old.G)*(1-a)),
		B: uint8(float64(c.B)*a + float64(old.B)*(1-a)),
		A: 0xff,
	})
}
