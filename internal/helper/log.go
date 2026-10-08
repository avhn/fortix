package helper

import (
	"bufio"
	"errors"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"golang.org/x/sys/unix"

	"github.com/avhn/fortix/internal/openfortivpn"
	"github.com/avhn/fortix/internal/protocol"
	"github.com/avhn/fortix/internal/session"
)

// logSize caps each of three retained log files, including the active file.
const logSize = 1024 * 1024

// rotatingLog serializes stdout/stderr writes and keeps only redacted diagnostics.
// The containing directory is private and checked before the helper starts.
type rotatingLog struct {
	mu      sync.Mutex
	dir     *os.File
	name    string
	file    *os.File
	size    int64
	secrets [][]byte
	maskAll bool
	ownsDir bool
}

// openLog opens a validated profile log without following symlinks. Existing files
// must be regular, privately readable, and owned by the effective helper user.
func openLog(dir, id string) (*rotatingLog, error) {
	f, err := openDirectory(dir)
	if err != nil {
		return nil, err
	}
	log, err := openLogAt(f, id)
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	log.ownsDir = true
	return log, nil
}

// openLogAt opens a private profile log within the server's pinned directory. The
// caller retains the directory handle until all log writers have stopped.
func openLogAt(dir *os.File, id string) (*rotatingLog, error) {
	if !ValidID(id) {
		return nil, errors.New("invalid log id")
	}
	name := id + ".log"
	f, err := privateFileAt(dir, name, unix.O_WRONLY|unix.O_APPEND|unix.O_CREAT)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &rotatingLog{dir: dir, name: name, file: f, size: st.Size()}, nil
}

// Close closes the active file after all writers have completed, returning I/O errors.
func (l *rotatingLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, secret := range l.secrets {
		clear(secret)
	}
	l.secrets = nil
	l.maskAll = true
	err := l.file.Close()
	if l.ownsDir {
		err = errors.Join(err, l.dir.Close())
	}
	return err
}

// write stores an already redacted, single diagnostic line with bounded rotation.
// Rotation never opens an old backup; renames replace directory entries, not targets.
func (l *rotatingLog) write(line string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	data := []byte(line + "\n")
	if len(data) > logSize {
		return errors.New("log line exceeds limit")
	}
	if l.size+int64(len(data)) > logSize {
		if err := l.file.Close(); err != nil {
			return err
		}
		if err := unix.Renameat(int(l.dir.Fd()), l.name+".1", int(l.dir.Fd()), l.name+".2"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := unix.Renameat(int(l.dir.Fd()), l.name, int(l.dir.Fd()), l.name+".1"); err != nil {
			return err
		}
		f, err := privateFileAt(l.dir, l.name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL)
		if err != nil {
			return err
		}
		l.file = f
		l.size = 0
	}
	n, err := l.file.Write(data)
	l.size += int64(n)
	return err
}

// Diagnostic patterns mask credential-labelled tails and Assuan data echoes. ANSI
// sequences are removed before matching so terminal decoration cannot hide labels.
var (
	credentialLabel = regexp.MustCompile(`(?i)\b(password|passwd|otp|token|cookie|svpncookie)\b["']?\s*[:=]\s*.*`)
	credentialWords = regexp.MustCompile(`(?i)\b(password|passwd|otp|token|cookie|svpncookie)\s+.+`)
	assuanData      = regexp.MustCompile(`(?:^|[\s:>])D[ \t]+.*`)
	ansiSequence    = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
)

// protect retains bounded, erasable copies of credentials before the child receives
// them. Excess answers and multi-record credentials disable diagnostics: line scanning
// could otherwise retain a fragment of a secret containing CR, LF, or NUL bytes.
func (l *rotatingLog) protect(secret []byte) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(secret) == 0 || l.maskAll {
		return
	}
	if len(l.secrets) >= 32 || strings.ContainsAny(string(secret), "\r\n\x00") {
		l.maskAll = true
		return
	}
	escaped := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A", "\x00", "%00").Replace(string(secret))
	l.secrets = append(l.secrets, append([]byte(nil), secret...), []byte(escaped))
}

// redact preserves diagnostic text while masking known answers, labelled secrets,
// and Assuan data records. It strips controls and caps output after redaction so
// truncation cannot turn a full secret into an unrecognizable partial disclosure.
func (l *rotatingLog) redact(line string) string {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.maskAll {
		return "child diagnostic [redacted]"
	}
	for _, secret := range l.secrets {
		line = strings.ReplaceAll(line, string(secret), "[redacted]")
	}
	line = ansiSequence.ReplaceAllString(line, "")
	line = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, line)
	// Decoration stripping can join bytes into a known answer; mask once more.
	for _, secret := range l.secrets {
		line = strings.ReplaceAll(line, string(secret), "[redacted]")
	}
	if assuanData.MatchString(line) {
		return "Assuan data [redacted]"
	}
	line = credentialLabel.ReplaceAllString(line, "$1=[redacted]")
	line = credentialWords.ReplaceAllString(line, "$1 [redacted]")
	if len(line) > 4096 {
		line = strings.ToValidUTF8(line[:4096], "") + " [truncated]"
	}
	return line
}

// drainAndWait drains both child pipes and reaps exactly one process. Exit is queued
// only after stdout observations, so buffered authentication/certificate failures
// cannot be mistaken for a transport reconnect. Leaked pipe holders get a short
// drain deadline after the leader exits rather than holding cleanup indefinitely.
func (a *supervisor) drainAndWait(cmd *exec.Cmd, stdout, stderr *os.File, attempt uint64, log *rotatingLog) {
	defer func() { _ = stdout.Close(); _ = stderr.Close() }()
	var drains sync.WaitGroup
	drains.Add(2)
	go func() { defer drains.Done(); a.scanOutput(stdout, attempt, log, true) }()
	go func() { defer drains.Done(); a.scanOutput(stderr, attempt, log, false) }()
	// Keep the leader unreaped until its group is killed: its PID cannot be reused
	// while it remains our child, even after entering the zombie state.
	if waitChild(cmd.Process.Pid) {
		_ = unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
	}
	err := cmd.Wait()
	_ = stdout.SetReadDeadline(time.Now().Add(time.Second))
	_ = stderr.SetReadDeadline(time.Now().Add(time.Second))
	drains.Wait()
	code := 0
	if err != nil {
		code = 1
	}
	a.send(session.Event{Profile: a.id, Attempt: attempt, Kind: session.ProcessExited, ExitCode: code, Jitter: 0.5})
}

// waitUntilFinished retains the child's reserved PID until inspection confirms exit
// or absence. Transient kernel/procfs errors are retried, never used to kill a tunnel.
// It returns true only while a confirmed zombie reserves the PID for group signalling.
// The injected inspector and interval allow deterministic failure-path tests.
func waitUntilFinished(pid int, inspect func(int) (bool, error), interval time.Duration) bool {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		exited, err := inspect(pid)
		if err == nil && exited {
			return true
		}
		if errors.Is(err, unix.ESRCH) || errors.Is(err, os.ErrNotExist) {
			// Absence no longer reserves the PID and cannot authorize a group signal.
			return false
		}
		<-ticker.C
	}
}

// scanOutput parses bounded stdout records and retains only redacted diagnostics
// from either stream. Overlong lines fail the attempt; scanner errors contain no
// input bytes. Parser state is isolated to this attempt's stdout stream.
func (a *supervisor) scanOutput(r io.Reader, attempt uint64, log *rotatingLog, stdout bool) {
	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 4096), protocol.MaxLine+1)
	parser := openfortivpn.Parser{}
	emit := func(event openfortivpn.Event) {
		a.send(session.Event{Profile: a.id, Attempt: attempt, Kind: session.Output, Observation: event, Jitter: 0.5})
	}
	for scanner.Scan() {
		line := log.redact(scanner.Text())
		if err := log.write(line); err != nil {
			a.send(session.Event{Profile: a.id, Attempt: attempt, Kind: session.AttemptFailed})
			return
		}
		a.server.emit(protocol.Event{Type: "log", Profile: a.id, Attempt: attempt, Line: line}, nil)
		if stdout {
			for _, event := range parser.Parse(scanner.Text()) {
				emit(event)
			}
		}
	}
	if stdout {
		for _, event := range parser.Flush() {
			emit(event)
		}
	}
	if scanner.Err() != nil {
		a.send(session.Event{Profile: a.id, Attempt: attempt, Kind: session.AttemptFailed})
	}
}

// readLogs returns the last requested lines across at most three bounded files.
// It refuses links, oversized files, and unsafe modes instead of exposing arbitrary
// data. Concurrent rotation may omit an old file, but cannot escape the log directory.
func readLogs(dir, id string, count int) ([]string, error) {
	f, err := openDirectory(dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return readLogsAt(f, id, count)
}

// readLogsAt reads a bounded tail relative to the held log directory, so parent
// renames cannot redirect reads. Missing rotated files are harmless during rotation.
func readLogsAt(dir *os.File, id string, count int) ([]string, error) {
	if !ValidID(id) || count < 1 || count > 500 {
		return nil, errors.New("invalid log request")
	}
	lines := make([]string, 0, count)
	for _, suffix := range []string{".2", ".1", ""} {
		f, err := privateFileAt(dir, id+".log"+suffix, unix.O_RDONLY)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		data, err := io.ReadAll(io.LimitReader(f, logSize+1))
		_ = f.Close()
		if err != nil || len(data) > logSize {
			return nil, errors.New("invalid log file")
		}
		for _, line := range strings.Split(strings.TrimSuffix(string(data), "\n"), "\n") {
			if line == "" {
				continue
			}
			if len(lines) == count {
				copy(lines, lines[1:])
				lines = lines[:count-1]
			}
			lines = append(lines, line)
		}
	}
	return lines, nil
}
