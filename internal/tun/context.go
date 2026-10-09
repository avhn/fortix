package tun

import (
	"context"
	"errors"
	"io"
	"time"
)

// packetContextReader interrupts a packet read without deleting its link.
type packetContextReader interface {
	ReadContext(context.Context, []byte) (int, error)
}

// packetContextWriter interrupts a packet write without deleting its link.
type packetContextWriter interface {
	WriteContext(context.Context, []byte) (int, error)
}

// readContext selects injected contextual I/O or kernel poller deadlines. Transports
// without either capability remain usable only for uncancellable legacy reads.
func readContext(ctx context.Context, r io.Reader, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if reader, ok := r.(packetContextReader); ok {
		return reader.ReadContext(ctx, p)
	}
	if reader, ok := r.(interface{ SetReadDeadline(time.Time) error }); ok {
		finish, err := interruptIO(ctx, reader.SetReadDeadline)
		if err != nil {
			return 0, err
		}
		n, err := r.Read(p)
		finish()
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return n, err
	}
	if ctx.Done() != nil {
		return 0, errors.New("tunnel transport does not support cancellable reads")
	}
	return r.Read(p)
}

// writeContext applies contextual I/O or finite poller deadlines to packet writes.
// Cancellation does not close the device and cannot race a later deadline reset.
func writeContext(ctx context.Context, w io.Writer, p []byte) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	if writer, ok := w.(packetContextWriter); ok {
		return writer.WriteContext(ctx, p)
	}
	if writer, ok := w.(interface{ SetWriteDeadline(time.Time) error }); ok {
		finish, err := interruptIO(ctx, writer.SetWriteDeadline)
		if err != nil {
			return 0, err
		}
		n, err := w.Write(p)
		finish()
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return n, err
	}
	if ctx.Done() != nil {
		return 0, errors.New("tunnel transport does not support cancellable writes")
	}
	return w.Write(p)
}

// interruptIO arms a context deadline and joins the cancellation callback before
// resetting it. A completed operation can never interrupt the next packet's I/O.
func interruptIO(ctx context.Context, set func(time.Time) error) (func(), error) {
	deadline, _ := ctx.Deadline()
	if err := set(deadline); err != nil {
		return nil, err
	}
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { _ = set(time.Now()); close(done) })
	return func() {
		if !stop() {
			<-done
		}
		_ = set(time.Time{})
	}, nil
}

// ReadContext consumes one fake packet with cancellation and no device closure.
func (f *fakePackets) ReadContext(ctx context.Context, p []byte) (int, error) {
	packet, err := f.receive(ctx, f.incoming)
	if err != nil {
		return 0, err
	}
	if len(p) < len(packet) {
		return 0, io.ErrShortBuffer
	}
	return copy(p, packet), nil
}

// WriteContext queues one copied fake packet under the caller's finite budget.
func (f *fakePackets) WriteContext(ctx context.Context, p []byte) (int, error) {
	if err := f.send(ctx, f.outgoing, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
