package attestation

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"

	"os"

	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

const spireSocketPath = "unix:///tmp/spire-agent/public/api.sock"
const svidDir = "/home/davi/UFCG/SPIREPersonalComputing/attestor_module"

type x509Watcher struct{}

func (x509Watcher) OnX509ContextUpdate(c *workloadapi.X509Context) {
	for i, svid := range c.SVIDs {
		cert, key, err := svid.Marshal()
		if err != nil {
			log.Fatalf("Unable to marshal X.509 SVID: %v", err)
		}

		log.Infof("SVID updated for %q\n", svid.ID)

		if err := os.WriteFile(fmt.Sprintf("%s/svids/svid%d.crt", svidDir, i), cert, 0644); err != nil {
			log.Fatalf("Failed to write SVID certificate to file: %v", err)
		}
		if err := os.WriteFile(fmt.Sprintf("%s/svids/svid%d.key", svidDir, i), key, 0600); err != nil {
			log.Fatalf("Failed to write SVID key to file: %v", err)
		}
	}
}

func (x509Watcher) OnX509ContextWatchError(err error) {
	log.Errorf("OnX509ContextWatchError error: %v", err)
}

func WatchForSVID(ctx context.Context) {
	defer log.Infof("SVID Watcher stopped")
	client, err := workloadapi.New(ctx, workloadapi.WithAddr(spireSocketPath))
	if err != nil {
		log.Fatalf("Unable to create workload API client: %v", err)
	}
	defer client.Close()

	if err := client.WatchX509Context(ctx, &x509Watcher{}); err != nil {
		log.Fatalf("Error watching X.509 context: %v", err)
	}
}
