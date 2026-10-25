package pxta

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Browser is a running headless Chrome or Chromium that PXTA drives.
type Browser struct {
	Path      string
	Version   string
	UserAgent string
	cdp       *CDP
	cmd       *exec.Cmd
	dataDir   string
	stderr    *tailBuffer
	waitOnce  sync.Once
	waitErr   error
	exited    chan struct{}
}

// FindBrowser looks for Chrome, Chromium or Edge. An explicit path wins, then
// PXTA_BROWSER and CHROME_PATH, then the usual names on PATH, then the usual
// install locations.
func FindBrowser(explicit string) (string, error) {
	for _, p := range []string{explicit, os.Getenv("PXTA_BROWSER"), os.Getenv("CHROME_PATH")} {
		if p == "" {
			continue
		}
		if lp, err := exec.LookPath(p); err == nil {
			return lp, nil
		}
		return "", fmt.Errorf("browser %q not found or not executable", p)
	}
	for _, name := range []string{"google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "chrome", "chrome-headless-shell", "headless_shell", "microsoft-edge", "msedge"} {
		if p, err := exec.LookPath(name); err == nil {
			return p, nil
		}
	}
	var cands []string
	switch runtime.GOOS {
	case "darwin":
		cands = []string{
			"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
			"/Applications/Chromium.app/Contents/MacOS/Chromium",
			"/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
		}
		if home, err := os.UserHomeDir(); err == nil {
			cands = append(cands, filepath.Join(home, "Applications/Google Chrome.app/Contents/MacOS/Google Chrome"))
		}
	case "windows":
		for _, env := range []string{"ProgramFiles", "ProgramFiles(x86)", "LocalAppData"} {
			if base := os.Getenv(env); base != "" {
				cands = append(cands,
					filepath.Join(base, `Google\Chrome\Application\chrome.exe`),
					filepath.Join(base, `Chromium\Application\chrome.exe`),
					filepath.Join(base, `Microsoft\Edge\Application\msedge.exe`))
			}
		}
	default:
		cands = []string{"/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser", "/snap/bin/chromium", "/opt/google/chrome/chrome"}
	}
	for _, p := range cands {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", errors.New("no Chrome, Chromium or Edge found: install one, or pass --browser /path/to/chrome (PXTA_BROWSER works too)")
}

// The newest browser started, for the crash test.
var (
	launchedMu      sync.Mutex
	lastLaunchedPid int
)

var devtoolsLine = regexp.MustCompile(`DevTools listening on (ws://\S+)`)

// LaunchOptions controls how the browser starts.
type LaunchOptions struct {
	Path      string
	ExtraArgs []string // used by the tests to point tracker hosts at local fixtures
	Timeout   time.Duration
}

// LaunchBrowser starts a headless browser with a throwaway profile.
func LaunchBrowser(ctx context.Context, o LaunchOptions) (*Browser, error) {
	path, err := FindBrowser(o.Path)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "pxta-profile-")
	if err != nil {
		return nil, err
	}
	args := []string{
		"--headless=new",
		"--remote-debugging-port=0",
		"--user-data-dir=" + dir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-background-networking",
		"--disable-component-update",
		"--disable-sync",
		"--disable-default-apps",
		"--disable-extensions",
		"--disable-domain-reliability",
		"--disable-client-side-phishing-detection",
		"--metrics-recording-only",
		"--mute-audio",
		"--hide-scrollbars",
		"--password-store=basic",
		"--use-mock-keychain",
		"--disable-features=Translate,OptimizationHints,MediaRouter,DialMediaRouteProvider,PrivacySandboxSettings4",
		"--window-size=1366,900",
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		args = append(args, "--no-sandbox")
	}
	args = append(args, o.ExtraArgs...)
	args = append(args, "about:blank")
	cmd := exec.Command(path, args...)
	tail := &tailBuffer{max: 8192}
	pr, pw, err := os.Pipe()
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	cmd.Stderr = pw
	cmd.Stdout = tail
	if err := cmd.Start(); err != nil {
		pw.Close()
		pr.Close()
		os.RemoveAll(dir)
		return nil, fmt.Errorf("starting %s: %w", path, err)
	}
	pw.Close()
	b := &Browser{Path: path, cmd: cmd, dataDir: dir, stderr: tail, exited: make(chan struct{})}
	launchedMu.Lock()
	lastLaunchedPid = cmd.Process.Pid
	launchedMu.Unlock()
	go func() {
		b.waitErr = cmd.Wait()
		close(b.exited)
	}()
	found := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		sent := false
		for sc.Scan() {
			line := sc.Text()
			tail.Write([]byte(line + "\n"))
			if !sent {
				if m := devtoolsLine.FindStringSubmatch(line); m != nil {
					found <- m[1]
					sent = true
				}
			}
		}
		pr.Close()
	}()
	timeout := o.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	var wsURL string
	select {
	case wsURL = <-found:
	case <-b.exited:
		b.cleanup()
		return nil, fmt.Errorf("%s exited before it was ready: %s", path, strings.TrimSpace(tail.String()))
	case <-time.After(timeout):
		b.Kill()
		return nil, fmt.Errorf("%s did not start within %s: %s", path, timeout, strings.TrimSpace(tail.String()))
	case <-ctx.Done():
		b.Kill()
		return nil, ctx.Err()
	}
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	c, err := DialCDP(cctx, wsURL)
	if err != nil {
		b.Kill()
		return nil, err
	}
	b.cdp = c
	var v struct {
		Product   string `json:"product"`
		UserAgent string `json:"userAgent"`
	}
	if err := c.Call(cctx, "", "Browser.getVersion", nil, &v); err != nil {
		b.Kill()
		return nil, err
	}
	b.Version, b.UserAgent = v.Product, v.UserAgent
	return b, nil
}

// Kill stops the browser and removes its profile.
func (b *Browser) Kill() {
	if b.cdp != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_ = b.cdp.Call(ctx, "", "Browser.close", nil, nil)
		cancel()
		b.cdp.Close()
	}
	select {
	case <-b.exited:
	case <-time.After(3 * time.Second):
		if b.cmd.Process != nil {
			b.cmd.Process.Kill()
		}
		<-b.exited
	}
	b.cleanup()
}

func (b *Browser) cleanup() {
	// Chrome may still hold files for a moment after exit on Windows.
	for i := 0; i < 5; i++ {
		if os.RemoveAll(b.dataDir) == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// Alive reports whether the browser process and its connection are up.
func (b *Browser) Alive() bool {
	select {
	case <-b.exited:
		return false
	case <-b.cdp.Done():
		return false
	default:
		return true
	}
}

// Pid is the browser's process ID (for the crash test).
func (b *Browser) Pid() int {
	if b.cmd.Process == nil {
		return 0
	}
	return b.cmd.Process.Pid
}

type tailBuffer struct {
	mu  sync.Mutex
	buf []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.buf = append(t.buf, p...)
	if len(t.buf) > t.max {
		t.buf = t.buf[len(t.buf)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.buf)
}
