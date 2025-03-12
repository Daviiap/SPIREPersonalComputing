package main

import (
	"context"

	"github.com/davi/attestor-cli/pkg/attestation"
	"github.com/davi/attestor-cli/pkg/utils"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go utils.WaitForCtrlC(cancel)

	attestation.ServeModule(ctx)
	attestation.WatchForSVID(ctx)
}
