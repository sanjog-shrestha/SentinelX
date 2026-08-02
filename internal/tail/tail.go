package tail

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"time"
)

func Follow(ctx context.Context, path string, out chan<- string) {
	for ctx.Err() == nil {
		f, err := os.Open(path)
		if err != nil {
			time.Sleep(2 * time.Second)
			continue
		}
		slog.Info("tailing", "path", path)
		followOpen(ctx, f, path, out)
		f.Close()
	}
}

func followOpen(ctx context.Context, f *os.File, path string, out chan<- string) {
	reader := bufio.NewReader(f)
	var consumed int64
	var pending string

	for ctx.Err() == nil {
		chunk, err := reader.ReadString('\n')
		consumed += int64(len(chunk))

		if err == nil {
			line := pending + chunk[:len(chunk)-1]
			pending = ""
			if line != "" {
				select {
				case out <- line:
				case <-ctx.Done():
					return
				}
			}
			continue
		}
		if err != io.EOF {
			slog.Warn("tail read error, reopening", "path", path, "err", err)
			return
		}

		pending += chunk
		time.Sleep(500 * time.Millisecond)

		info, statErr := os.Stat(path)
		if statErr != nil || info.Size() < consumed {
			slog.Info("file rotated or removed, reopening", "path", path)
			return
		}
	}
}
