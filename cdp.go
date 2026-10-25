package pxta

// A minimal Chrome DevTools Protocol client over WebSocket, written with the
// standard library only. PXTA needs a small part of the protocol: send a
// command and wait for its result, and receive events. Sessions are
// "flattened", so every target (page, iframe, worker) is reached through the
// one browser connection, told apart by its sessionId.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const maxMessage = 256 << 20 // largest DevTools message accepted (256 MiB)

// wsConn is a client-side WebSocket connection (RFC 6455), text frames only.
type wsConn struct {
	conn net.Conn
	r    *bufio.Reader
	wmu  sync.Mutex
}

func dialWS(ctx context.Context, rawURL string) (*wsConn, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "ws" {
		return nil, fmt.Errorf("devtools: unsupported scheme %q", u.Scheme)
	}
	var d net.Dialer
	c, err := d.DialContext(ctx, "tcp", u.Host)
	if err != nil {
		return nil, err
	}
	keyBytes := make([]byte, 16)
	if _, err := rand.Read(keyBytes); err != nil {
		c.Close()
		return nil, err
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)
	path := u.RequestURI()
	req := "GET " + path + " HTTP/1.1\r\n" +
		"Host: " + u.Host + "\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + key + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	if dl, ok := ctx.Deadline(); ok {
		c.SetDeadline(dl)
	}
	if _, err := io.WriteString(c, req); err != nil {
		c.Close()
		return nil, err
	}
	br := bufio.NewReaderSize(c, 1<<16)
	resp, err := http.ReadResponse(br, &http.Request{Method: "GET"})
	if err != nil {
		c.Close()
		return nil, fmt.Errorf("devtools handshake: %w", err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		c.Close()
		return nil, fmt.Errorf("devtools handshake: status %s", resp.Status)
	}
	h := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	if resp.Header.Get("Sec-WebSocket-Accept") != base64.StdEncoding.EncodeToString(h[:]) {
		c.Close()
		return nil, errors.New("devtools handshake: bad Sec-WebSocket-Accept")
	}
	c.SetDeadline(time.Time{})
	return &wsConn{conn: c, r: br}, nil
}

func (w *wsConn) writeFrame(op byte, payload []byte) error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	hdr := make([]byte, 0, 14)
	hdr = append(hdr, 0x80|op)
	n := len(payload)
	switch {
	case n < 126:
		hdr = append(hdr, 0x80|byte(n))
	case n <= 0xFFFF:
		hdr = append(hdr, 0x80|126, byte(n>>8), byte(n))
	default:
		hdr = append(hdr, 0x80|127)
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], uint64(n))
		hdr = append(hdr, b[:]...)
	}
	var mask [4]byte
	if _, err := rand.Read(mask[:]); err != nil {
		return err
	}
	hdr = append(hdr, mask[:]...)
	masked := make([]byte, n)
	for i := 0; i < n; i++ {
		masked[i] = payload[i] ^ mask[i%4]
	}
	if _, err := w.conn.Write(append(hdr, masked...)); err != nil {
		return err
	}
	return nil
}

func (w *wsConn) WriteText(b []byte) error { return w.writeFrame(0x1, b) }

// ReadMessage returns the next complete text or binary message, answering
// pings and joining fragments on the way.
func (w *wsConn) ReadMessage() ([]byte, error) {
	var msg []byte
	for {
		var h [2]byte
		if _, err := io.ReadFull(w.r, h[:]); err != nil {
			return nil, err
		}
		fin := h[0]&0x80 != 0
		op := h[0] & 0x0F
		masked := h[1]&0x80 != 0
		n := uint64(h[1] & 0x7F)
		switch n {
		case 126:
			var b [2]byte
			if _, err := io.ReadFull(w.r, b[:]); err != nil {
				return nil, err
			}
			n = uint64(binary.BigEndian.Uint16(b[:]))
		case 127:
			var b [8]byte
			if _, err := io.ReadFull(w.r, b[:]); err != nil {
				return nil, err
			}
			n = binary.BigEndian.Uint64(b[:])
		}
		if n > maxMessage || uint64(len(msg))+n > maxMessage {
			return nil, errors.New("devtools: message too large")
		}
		var mask [4]byte
		if masked {
			if _, err := io.ReadFull(w.r, mask[:]); err != nil {
				return nil, err
			}
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(w.r, payload); err != nil {
			return nil, err
		}
		if masked {
			for i := range payload {
				payload[i] ^= mask[i%4]
			}
		}
		switch op {
		case 0x8: // close
			_ = w.writeFrame(0x8, nil)
			return nil, io.EOF
		case 0x9: // ping
			if err := w.writeFrame(0xA, payload); err != nil {
				return nil, err
			}
			continue
		case 0xA: // pong
			continue
		}
		msg = append(msg, payload...)
		if fin {
			return msg, nil
		}
	}
}

func (w *wsConn) Close() error { return w.conn.Close() }

// cdpError is an error answer from the browser.
type cdpError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    string `json:"data"`
}

func (e *cdpError) Error() string {
	if e.Data != "" {
		return fmt.Sprintf("devtools: %s (%s)", e.Message, e.Data)
	}
	return "devtools: " + e.Message
}

type cdpMessage struct {
	ID        int64           `json:"id,omitempty"`
	SessionID string          `json:"sessionId,omitempty"`
	Method    string          `json:"method,omitempty"`
	Params    json.RawMessage `json:"params,omitempty"`
	Result    json.RawMessage `json:"result,omitempty"`
	Error     *cdpError       `json:"error,omitempty"`
}

// Event is a DevTools event, with the session it came from.
type Event struct {
	SessionID string
	Method    string
	Params    json.RawMessage
}

// CDP is a connection to the browser target.
type CDP struct {
	ws     *wsConn
	mu     sync.Mutex
	nextID int64
	wait   map[int64]chan cdpMessage
	subs   map[int]func(Event)
	subID  int
	closed chan struct{}
	err    error
}

// ErrClosed is returned once the browser connection is gone.
var ErrClosed = errors.New("devtools: browser connection closed")

func DialCDP(ctx context.Context, wsURL string) (*CDP, error) {
	ws, err := dialWS(ctx, wsURL)
	if err != nil {
		return nil, err
	}
	c := &CDP{ws: ws, wait: map[int64]chan cdpMessage{}, subs: map[int]func(Event){}, closed: make(chan struct{})}
	go c.readLoop()
	return c, nil
}

func (c *CDP) readLoop() {
	var err error
	for {
		var b []byte
		b, err = c.ws.ReadMessage()
		if err != nil {
			break
		}
		var m cdpMessage
		if json.Unmarshal(b, &m) != nil {
			continue
		}
		if m.ID != 0 {
			c.mu.Lock()
			ch := c.wait[m.ID]
			delete(c.wait, m.ID)
			c.mu.Unlock()
			if ch != nil {
				ch <- m
			}
			continue
		}
		if m.Method != "" {
			c.mu.Lock()
			subs := make([]func(Event), 0, len(c.subs))
			for _, f := range c.subs {
				subs = append(subs, f)
			}
			c.mu.Unlock()
			ev := Event{SessionID: m.SessionID, Method: m.Method, Params: m.Params}
			for _, f := range subs {
				f(ev)
			}
		}
	}
	c.mu.Lock()
	c.err = err
	for id, ch := range c.wait {
		close(ch)
		delete(c.wait, id)
	}
	c.mu.Unlock()
	close(c.closed)
}

// Subscribe registers f for every event. f runs on the reader goroutine and
// must not block or call Call; hand work to another goroutine instead.
func (c *CDP) Subscribe(f func(Event)) (cancel func()) {
	c.mu.Lock()
	c.subID++
	id := c.subID
	c.subs[id] = f
	c.mu.Unlock()
	return func() {
		c.mu.Lock()
		delete(c.subs, id)
		c.mu.Unlock()
	}
}

// Call sends a command and waits for its result. result may be nil.
func (c *CDP) Call(ctx context.Context, session, method string, params any, result any) error {
	var raw json.RawMessage
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return err
		}
		raw = b
	}
	ch := make(chan cdpMessage, 1)
	c.mu.Lock()
	select {
	case <-c.closed:
		c.mu.Unlock()
		return ErrClosed
	default:
	}
	c.nextID++
	id := c.nextID
	c.wait[id] = ch
	c.mu.Unlock()
	b, err := json.Marshal(cdpMessage{ID: id, SessionID: session, Method: method, Params: raw})
	if err != nil {
		return err
	}
	if err := c.ws.WriteText(b); err != nil {
		c.mu.Lock()
		delete(c.wait, id)
		c.mu.Unlock()
		return ErrClosed
	}
	select {
	case m, ok := <-ch:
		if !ok {
			return ErrClosed
		}
		if m.Error != nil {
			return m.Error
		}
		if result != nil && len(m.Result) > 0 {
			return json.Unmarshal(m.Result, result)
		}
		return nil
	case <-ctx.Done():
		c.mu.Lock()
		delete(c.wait, id)
		c.mu.Unlock()
		return ctx.Err()
	case <-c.closed:
		return ErrClosed
	}
}

// Done is closed when the connection ends.
func (c *CDP) Done() <-chan struct{} { return c.closed }

func (c *CDP) Close() error { return c.ws.Close() }

// isClosed reports whether err means the browser went away.
func isClosed(err error) bool {
	return errors.Is(err, ErrClosed) || (err != nil && strings.Contains(err.Error(), "use of closed network connection"))
}
