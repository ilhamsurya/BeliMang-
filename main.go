package main

import (
	"context"
	"projectsphere/beli-mang/config"
	"projectsphere/beli-mang/pkg/middleware/graceful"
	"projectsphere/beli-mang/pkg/middleware/logger"
	"projectsphere/beli-mang/pkg/protocol/httpListener"
	"time"

	_ "github.com/lib/pq"
)

func main() {
	logger.InitLogger()
	config.LoadConfig(".env")

	httpProtocol := httpListener.Start()
	graceful.GracefulShutdown(
		context.TODO(),
		time.Duration(5*time.Second),
		map[string]graceful.Operation{
			"http": func(ctx context.Context) error {
				return httpProtocol.Shutdown(ctx)
			},
		},
	)

	httpProtocol.Listen()
}
