package pxta

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Request is one network request recorded during a page visit.
type Request struct {
	Pass        string            `json:"pass"`
	Page        int               `json:"page"`
	Time        time.Time         `json:"time"`
	URL         string            `json:"url"`
	Method      string            `json:"method"`
	Type        string            `json:"type"`
	ContentType string            `json:"content_type,omitempty"`
	Body        string            `json:"body,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	Target      string            `json:"target"` // page, iframe, worker, service_worker, shared_worker
	Phase       string            `json:"phase"`  // load, interact, unload
}

// Visit is one page load in one pass.
type Visit struct {
	Pass     string    `json:"pass"`
	Page     int       `json:"page"`
	URL      string    `json:"url"`
	FinalURL string    `json:"final_url"`
	Title    string    `json:"title,omitempty"`
	Started  time.Time `json:"started"`
	Error    string    `json:"error,omitempty"`
	Requests int       `json:"requests"`
	Links    []string  `json:"-"`
	Emails   []string  `json:"-"`
}

type frameCtx struct {
	session string
	ctxID   int
}

// pageRecorder follows one tab and everything attached to it.
type pageRecorder struct {
	b        *Browser
	pass     string
	page     int
	mu       sync.Mutex
	sessions map[string]string // sessionId -> target type
	reqs     map[string]*Request
	order    []string
	contexts map[string]frameCtx // execution contexts by "session/id"
	phase    string
	last     time.Time
	loaded   chan struct{}
	loadOnce sync.Once
	work     chan func()
	done     chan struct{}
}

func newPageRecorder(b *Browser, pass string, page int, root string) *pageRecorder {
	r := &pageRecorder{b: b, pass: pass, page: page, sessions: map[string]string{root: "page"}, reqs: map[string]*Request{},
		contexts: map[string]frameCtx{}, phase: "load", last: time.Now(), loaded: make(chan struct{}), work: make(chan func(), 1024), done: make(chan struct{})}
	go func() {
		for {
			select {
			case f := <-r.work:
				f()
			case <-r.done:
				return
			}
		}
	}()
	return r
}

func (r *pageRecorder) queue(f func()) {
	select {
	case r.work <- f:
	default:
		go f() // never block the reader goroutine
	}
}

func (r *pageRecorder) stop() { close(r.done) }

func (r *pageRecorder) onEvent(ev Event) {
	r.mu.Lock()
	_, mine := r.sessions[ev.SessionID]
	r.mu.Unlock()
	if !mine {
		return
	}
	switch ev.Method {
	case "Network.requestWillBeSent":
		var p struct {
			RequestID string `json:"requestId"`
			Type      string `json:"type"`
			Request   struct {
				URL         string            `json:"url"`
				URLFragment string            `json:"urlFragment"`
				Method      string            `json:"method"`
				Headers     map[string]string `json:"headers"`
				PostData    string            `json:"postData"`
				HasPostData bool              `json:"hasPostData"`
				PostEntries []struct {
					Bytes string `json:"bytes"`
				} `json:"postDataEntries"`
			} `json:"request"`
		}
		if json.Unmarshal(ev.Params, &p) != nil {
			return
		}
		if strings.HasPrefix(p.Request.URL, "data:") || strings.HasPrefix(p.Request.URL, "blob:") {
			return
		}
		ct := ""
		for k, v := range p.Request.Headers {
			if strings.EqualFold(k, "content-type") {
				ct = v
			}
		}
		body := p.Request.PostData
		if body == "" && len(p.Request.PostEntries) > 0 {
			var sb strings.Builder
			for _, e := range p.Request.PostEntries {
				if b, ok := decodeStdBase64(e.Bytes); ok {
					sb.WriteString(b)
				}
			}
			body = sb.String()
		}
		r.mu.Lock()
		typ := r.sessions[ev.SessionID]
		key := ev.SessionID + "/" + p.RequestID
		if _, dup := r.reqs[key]; dup {
			// A redirect reuses the request ID; keep each hop.
			key = fmt.Sprintf("%s#%d", key, len(r.order))
		}
		req := &Request{Pass: r.pass, Page: r.page, Time: time.Now().UTC(), URL: p.Request.URL, Method: p.Request.Method,
			Type: p.Type, ContentType: ct, Body: body, Target: typ, Phase: r.phase, Headers: keepHeaders(p.Request.Headers)}
		r.reqs[key] = req
		r.order = append(r.order, key)
		r.last = time.Now()
		r.mu.Unlock()
		if p.Request.HasPostData && body == "" {
			sess, id := ev.SessionID, p.RequestID
			r.queue(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var res struct {
					PostData string `json:"postData"`
				}
				if r.b.cdp.Call(ctx, sess, "Network.getRequestPostData", map[string]any{"requestId": id}, &res) == nil {
					r.mu.Lock()
					req.Body = res.PostData
					r.mu.Unlock()
				}
			})
		}
	case "Page.loadEventFired":
		r.loadOnce.Do(func() { close(r.loaded) })
	case "Runtime.executionContextCreated":
		var p struct {
			Context struct {
				ID      int `json:"id"`
				AuxData struct {
					IsDefault bool   `json:"isDefault"`
					FrameID   string `json:"frameId"`
				} `json:"auxData"`
			} `json:"context"`
		}
		if json.Unmarshal(ev.Params, &p) == nil && p.Context.AuxData.IsDefault {
			r.mu.Lock()
			r.contexts[fmt.Sprintf("%s/%d", ev.SessionID, p.Context.ID)] = frameCtx{session: ev.SessionID, ctxID: p.Context.ID}
			r.mu.Unlock()
		}
	case "Runtime.executionContextDestroyed":
		var p struct {
			ID int `json:"executionContextId"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			r.mu.Lock()
			delete(r.contexts, fmt.Sprintf("%s/%d", ev.SessionID, p.ID))
			r.mu.Unlock()
		}
	case "Runtime.executionContextsCleared":
		r.mu.Lock()
		for k, c := range r.contexts {
			if c.session == ev.SessionID {
				delete(r.contexts, k)
			}
		}
		r.mu.Unlock()
	case "Target.attachedToTarget":
		var p struct {
			SessionID  string `json:"sessionId"`
			TargetInfo struct {
				Type string `json:"type"`
			} `json:"targetInfo"`
			Waiting bool `json:"waitingForDebugger"`
		}
		if json.Unmarshal(ev.Params, &p) != nil {
			return
		}
		r.mu.Lock()
		r.sessions[p.SessionID] = p.TargetInfo.Type
		r.mu.Unlock()
		child := p.SessionID
		r.queue(func() { r.setupChild(child, p.TargetInfo.Type) })
	case "Target.detachedFromTarget":
		// Keep the session in the map, since late events still belong to
		// this page, but forget its frames: they can't run scripts now.
		var p struct {
			SessionID string `json:"sessionId"`
		}
		if json.Unmarshal(ev.Params, &p) == nil {
			r.mu.Lock()
			for k, c := range r.contexts {
				if c.session == p.SessionID {
					delete(r.contexts, k)
				}
			}
			r.mu.Unlock()
		}
	}
}

func keepHeaders(h map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range h {
		switch strings.ToLower(k) {
		case "content-type", "referer":
			out[k] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (r *pageRecorder) setupChild(sess, typ string) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c := r.b.cdp
	_ = c.Call(ctx, sess, "Network.enable", map[string]any{"maxPostDataSize": 1 << 20}, nil)
	if typ == "iframe" || typ == "page" {
		_ = c.Call(ctx, sess, "Runtime.enable", nil, nil)
		_ = c.Call(ctx, sess, "Page.enable", nil, nil)
	}
	_ = c.Call(ctx, sess, "Target.setAutoAttach", map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}, nil)
	_ = c.Call(ctx, sess, "Runtime.runIfWaitingForDebugger", nil, nil)
}

func (r *pageRecorder) setPhase(p string) {
	r.mu.Lock()
	r.phase = p
	r.mu.Unlock()
}

// requests returns what was recorded so far, in order.
func (r *pageRecorder) requests() []Request {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Request, 0, len(r.order))
	for _, k := range r.order {
		out = append(out, *r.reqs[k])
	}
	return out
}

// waitIdle returns when no request has started for idle, or at deadline.
func (r *pageRecorder) waitIdle(ctx context.Context, idle time.Duration, deadline time.Time) {
	for {
		r.mu.Lock()
		quiet := time.Since(r.last)
		r.mu.Unlock()
		if quiet >= idle || time.Now().After(deadline) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// frames lists the default execution contexts of the page and its frames.
func (r *pageRecorder) frames() []frameCtx {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]frameCtx, 0, len(r.contexts))
	for _, c := range r.contexts {
		out = append(out, c)
	}
	return out
}

// eval runs JavaScript in a frame and decodes its JSON-able result.
func (b *Browser) eval(ctx context.Context, f frameCtx, expr string, out any) error {
	params := map[string]any{"expression": expr, "returnByValue": true, "awaitPromise": true}
	if f.ctxID != 0 {
		params["contextId"] = f.ctxID
	}
	var res struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		Exception *struct {
			Text string `json:"text"`
		} `json:"exceptionDetails"`
	}
	if err := b.cdp.Call(ctx, f.session, "Runtime.evaluate", params, &res); err != nil {
		return err
	}
	if res.Exception != nil {
		return fmt.Errorf("script error: %s", res.Exception.Text)
	}
	if out != nil && len(res.Result.Value) > 0 {
		return json.Unmarshal(res.Result.Value, out)
	}
	return nil
}

// tab is an open page with a recorder attached.
type tab struct {
	b        *Browser
	targetID string
	session  string
	rec      *pageRecorder
	unsub    func()
}

func (b *Browser) newContext(ctx context.Context) (string, error) {
	var res struct {
		ID string `json:"browserContextId"`
	}
	err := b.cdp.Call(ctx, "", "Target.createBrowserContext", map[string]any{"disposeOnDetach": true}, &res)
	return res.ID, err
}

func (b *Browser) disposeContext(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = b.cdp.Call(ctx, "", "Target.disposeBrowserContext", map[string]any{"browserContextId": id}, nil)
}

func (b *Browser) openTab(ctx context.Context, browserCtx, pass string, page int, userAgent string) (*tab, error) {
	var t struct {
		TargetID string `json:"targetId"`
	}
	if err := b.cdp.Call(ctx, "", "Target.createTarget", map[string]any{"url": "about:blank", "browserContextId": browserCtx}, &t); err != nil {
		return nil, err
	}
	var a struct {
		SessionID string `json:"sessionId"`
	}
	if err := b.cdp.Call(ctx, "", "Target.attachToTarget", map[string]any{"targetId": t.TargetID, "flatten": true}, &a); err != nil {
		return nil, err
	}
	rec := newPageRecorder(b, pass, page, a.SessionID)
	tb := &tab{b: b, targetID: t.TargetID, session: a.SessionID, rec: rec}
	tb.unsub = b.cdp.Subscribe(rec.onEvent)
	s := a.SessionID
	steps := []struct {
		m string
		p any
	}{
		{"Page.enable", nil},
		{"Runtime.enable", nil},
		{"Network.enable", map[string]any{"maxPostDataSize": 1 << 20}},
		{"Network.setCacheDisabled", map[string]any{"cacheDisabled": true}},
		{"Target.setAutoAttach", map[string]any{"autoAttach": true, "waitForDebuggerOnStart": true, "flatten": true}},
	}
	if userAgent != "" {
		steps = append(steps, struct {
			m string
			p any
		}{"Network.setUserAgentOverride", map[string]any{"userAgent": userAgent}})
	}
	for _, st := range steps {
		if err := b.cdp.Call(ctx, s, st.m, st.p, nil); err != nil {
			tb.close()
			return nil, fmt.Errorf("%s: %w", st.m, err)
		}
	}
	return tb, nil
}

func (t *tab) navigate(ctx context.Context, url string) error {
	var res struct {
		ErrorText string `json:"errorText"`
	}
	if err := t.b.cdp.Call(ctx, t.session, "Page.navigate", map[string]any{"url": url}, &res); err != nil {
		return err
	}
	if res.ErrorText != "" {
		return fmt.Errorf("could not load %s: %s", url, res.ErrorText)
	}
	return nil
}

// close leaves the page (so unload beacons fire and are recorded), then
// closes the tab.
func (t *tab) close() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = t.b.cdp.Call(ctx, "", "Target.closeTarget", map[string]any{"targetId": t.targetID}, nil)
	if t.unsub != nil {
		t.unsub()
	}
	t.rec.stop()
}

// leaveJS fires the events a page gets when the visitor leaves. Chrome
// doesn't report requests from a document that has already gone, so PXTA
// raises these events while the page is still there, records what they
// send, and only then navigates away.
const leaveJS = `(() => {
  try {
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' });
    Object.defineProperty(document, 'hidden', { configurable: true, get: () => true });
  } catch (e) {}
  document.dispatchEvent(new Event('visibilitychange'));
  window.dispatchEvent(new PageTransitionEvent('pagehide', { persisted: false }));
  window.dispatchEvent(new Event('beforeunload'));
  window.dispatchEvent(new Event('unload'));
  return true;
})()`

func (t *tab) leave(ctx context.Context, wait time.Duration) {
	t.rec.setPhase("unload")
	for _, f := range t.rec.frames() {
		cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		_ = t.b.eval(cctx, f, leaveJS, nil)
		cancel()
	}
	select {
	case <-time.After(wait):
	case <-ctx.Done():
	}
	_ = t.navigate(ctx, "about:blank")
	select {
	case <-time.After(300 * time.Millisecond):
	case <-ctx.Done():
	}
}

func decodeStdBase64(s string) (string, bool) {
	b, err := base64Std.DecodeString(s)
	if err != nil {
		return "", false
	}
	return string(b), true
}
