package dnsctx

import (
	"context"
	"log/slog"
)

// Id returns a slog.Attr that either is empty or contains the request id as added by the id handler.
func Id(ctx context.Context) slog.Attr {
	id := slog.Attr{}
	if x := Value(ctx, "id/id"); x != nil {
		id = slog.String("id", x.(string))
	}
	return id
}
