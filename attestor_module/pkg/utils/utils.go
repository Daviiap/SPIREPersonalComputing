package utils

import (
	"context"

	log "github.com/sirupsen/logrus"

	"os"
	"os/signal"
	"syscall"
)

func WaitForCtrlC(cancel context.CancelFunc) {
	signalCh := make(chan os.Signal, 1)
	signal.Notify(signalCh, os.Interrupt, syscall.SIGTERM)
	<-signalCh

	log.Info("Ctrl+C received, stopping all processes")
	cancel()
}
