//go:build windows

package prompt

import (
	"context"
	"errors"
	"io"
	"os"
	"os/signal"
	"syscall"
	"unicode/utf16"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// readConsoleInput binds only the missing console-record API from the system DLL.
var readConsoleInput = windows.NewLazySystemDLL("kernel32.dll").NewProc("ReadConsoleInputW")

// inputRecord matches INPUT_RECORD, including the key event's four-byte alignment.
type inputRecord struct {
	EventType uint16
	Padding   uint16
	Key       keyEventRecord
}

// keyEventRecord mirrors KEY_EVENT_RECORD without platform-dependent Go bool fields.
type keyEventRecord struct {
	Down       int32
	Repeat     uint16
	VirtualKey uint16
	ScanCode   uint16
	Char       uint16
	Control    uint32
}

// consoleKey is the injectable portion of an input record used by the line editor.
type consoleKey struct {
	char   uint16
	repeat uint16
	down   bool
}

// lineEditor bounds UTF-8 output while assembling UTF-16 surrogate pairs from key events.
// Its buffer is cleared by the caller after copying a successful response.
type lineEditor struct {
	data    []byte
	pending uint16
}

// step applies one UTF-16 key, with scalar-aware backspace and explicit cancellation.
// Unpaired surrogates fail rather than silently changing the supplied password.
func (e *lineEditor) step(char uint16) (bool, error) {
	switch char {
	case 3:
		return false, ErrCancelled
	case '\r', '\n':
		if e.pending != 0 {
			return false, ErrFailed
		}
		return true, nil
	case '\b':
		if e.pending != 0 {
			e.pending = 0
		} else if len(e.data) != 0 {
			_, size := utf8.DecodeLastRune(e.data)
			clear(e.data[len(e.data)-size:])
			e.data = e.data[:len(e.data)-size]
		}
		return false, nil
	case 0:
		return false, nil
	}
	var value rune
	if char >= 0xd800 && char <= 0xdbff {
		if e.pending != 0 || len(e.data) == maxInput {
			return false, ErrFailed
		}
		e.pending = char
		return false, nil
	}
	if char >= 0xdc00 && char <= 0xdfff {
		if e.pending == 0 {
			return false, ErrFailed
		}
		value = utf16.DecodeRune(rune(e.pending), rune(char))
		e.pending = 0
	} else {
		if e.pending != 0 {
			return false, ErrFailed
		}
		value = rune(char)
	}
	if len(e.data)+utf8.RuneLen(value) > maxInput {
		return false, ErrFailed
	}
	e.data = utf8.AppendRune(e.data, value)
	return false, nil
}

// editConsoleLine consumes injected key events without buffering a later response.
// Signals and context cancellation discard the buffer; key-up events never add text.
func editConsoleLine(ctx, interrupted context.Context, next func() (consoleKey, error)) ([]byte, error) {
	var editor lineEditor
	defer func() { clear(editor.data); editor.pending = 0 }()
	for {
		if interrupted.Err() != nil {
			return nil, ErrCancelled
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		key, err := next()
		if err != nil {
			return nil, err
		}
		if interrupted.Err() != nil {
			return nil, ErrCancelled
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !key.down {
			continue
		}
		for i := uint16(0); i < key.repeat; i++ {
			done, err := editor.step(key.char)
			if err != nil {
				return nil, err
			}
			if done {
				return append([]byte(nil), editor.data...), nil
			}
		}
	}
}

// hiddenPassword disables echo and processed input, restoring the full console mode.
// Ctrl+C arrives as a key event, while externally delivered interrupts cancel the read.
// Restoration failure discards the response and never returns a password with an error.
func hiddenPassword(ctx context.Context, fd int) (password []byte, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	h := windows.Handle(fd)
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return boundedNonConsole(ctx, fd)
	}
	interrupted, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer func() {
		if restoreErr := windows.SetConsoleMode(h, mode); restoreErr != nil {
			clear(password)
			password, err = nil, restoreErr
		}
	}()
	if err := disableEcho(fd); err != nil {
		return nil, err
	}
	return readHiddenLine(ctx, interrupted, fd)
}

// disableEcho switches to raw key records and disables quick-edit's blocking selection mode.
func disableEcho(fd int) error {
	h := windows.Handle(fd)
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return err
	}
	mode &^= windows.ENABLE_ECHO_INPUT | windows.ENABLE_LINE_INPUT | windows.ENABLE_PROCESSED_INPUT | windows.ENABLE_QUICK_EDIT_MODE | windows.ENABLE_VIRTUAL_TERMINAL_INPUT
	return windows.SetConsoleMode(h, mode|windows.ENABLE_EXTENDED_FLAGS)
}

// readHiddenLine waits in short intervals so cancellation leaves no blocked reader goroutine.
// ReadConsoleInputW consumes one record only after the console handle becomes signaled.
func readHiddenLine(ctx, interrupted context.Context, fd int) ([]byte, error) {
	h := windows.Handle(fd)
	return editConsoleLine(ctx, interrupted, func() (consoleKey, error) {
		ready, err := windows.WaitForMultipleObjects([]windows.Handle{h}, false, 50)
		if err != nil {
			return consoleKey{}, err
		}
		if ready == uint32(windows.WAIT_TIMEOUT) {
			return consoleKey{}, nil
		}
		if ready != windows.WAIT_OBJECT_0 {
			return consoleKey{}, ErrFailed
		}
		var record inputRecord
		var count uint32
		ok, _, err := readConsoleInput.Call(uintptr(h), uintptr(unsafe.Pointer(&record)), 1, uintptr(unsafe.Pointer(&count)))
		if ok == 0 {
			if errors.Is(err, windows.ERROR_SUCCESS) {
				err = ErrFailed
			}
			return consoleKey{}, err
		}
		if count != 1 {
			return consoleKey{}, io.EOF
		}
		if record.EventType != 1 {
			return consoleKey{}, nil
		}
		return consoleKey{record.Key.Char, record.Key.Repeat, record.Key.Down != 0}, nil
	})
}

// boundedNonConsole uses the shared unbuffered line reader on a duplicate owned handle.
// Like arbitrary Reader input, synchronous non-console input requires caller-owned cancellation.
func boundedNonConsole(ctx context.Context, fd int) ([]byte, error) {
	var duplicate windows.Handle
	process := windows.CurrentProcess()
	if err := windows.DuplicateHandle(process, windows.Handle(fd), process, &duplicate, 0, false, windows.DUPLICATE_SAME_ACCESS); err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(duplicate), "prompt-input")
	defer func() { _ = file.Close() }()
	line, err := readLine(file)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return []byte(line), nil
}
