package helper

import (
	"errors"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"unicode"
)

// logSize caps each of three retained log files, including the active file.
const logSize = 1024 * 1024

// rotatingLog serializes stdout/stderr writes and keeps only redacted diagnostics.
// The containing directory is private and checked before the helper starts.
type rotatingLog struct {
	mu      sync.Mutex
	dir     *helperDirectory
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
func openLogAt(dir *helperDirectory, id string) (*rotatingLog, error) {
	if !ValidID(id) {
		return nil, errors.New("invalid log id")
	}
	name := id + ".log"
	f, err := privateFileAt(dir, name, os.O_WRONLY|os.O_APPEND|os.O_CREATE)
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
		if err := renamePrivateAt(l.dir, l.name+".1", l.name+".2"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := renamePrivateAt(l.dir, l.name, l.name+".1"); err != nil {
			return err
		}
		f, err := privateFileAt(l.dir, l.name, os.O_WRONLY|os.O_CREATE|os.O_EXCL)
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
func readLogsAt(dir *helperDirectory, id string, count int) ([]string, error) {
	if !ValidID(id) || count < 1 || count > 500 {
		return nil, errors.New("invalid log request")
	}
	lines := make([]string, 0, count)
	for _, suffix := range []string{".2", ".1", ""} {
		f, err := privateFileAt(dir, id+".log"+suffix, os.O_RDONLY)
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
