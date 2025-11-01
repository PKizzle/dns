package url

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func (u *Url) Refetch() error {
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	go func() {
		for {
			select {
			case <-ticker.C:
				err := u.Fetch()
				if err != nil {
					alog := log.With(slog.String("url", u.URL), slog.String("file", filepath.Base(u.Path)))
					alog.Error("Failed to fetch", Err(err))
					continue
				}
			case <-u.ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (u *Url) Fetch() error {
	c := http.Client{Timeout: 10 * time.Second}
	buf := &bytes.Buffer{}
	resp, err := c.Post(u.URL, "*/*", buf)
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status code was not %d: %d", http.StatusOK, resp.StatusCode)
	}
	f, err := os.CreateTemp(filepath.Dir(u.Path), "xxxxx.transferred")
	if err != nil {
		return err
	}
	if err := os.WriteFile(f.Name(), buf.Bytes(), 0600); err != nil {
		return err
	}
	defer f.Close()
	defer os.Remove(f.Name())
	return os.Rename(f.Name(), u.Path)
}
