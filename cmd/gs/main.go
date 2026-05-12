package main

import (
	"fmt"
	"log"

	"github.com/matvejefimovyh/ghost-ship/internal/config"
	"github.com/matvejefimovyh/ghost-ship/pkg/sshutil"
)

const banner = `
  ____ _                      _        ____  _     _        
 / ___| |__   ___  ___| |_     / ___|| |__ (_)_ __  
| |  _| '_ \ / _ \/ __| __|____\___ \| '_ \| | '_ \ 
| |_| | | | | (_) \__ \ |_|_____|___) | | | | | |_) |
 \____|_| |_|\___/|___/\__|    |____/|_| |_|_| .__/ 
                                             |_|    
   Velesys Infrastructure Engine | v0.1.0-alpha
`

func main() {
	fmt.Println(banner)

	cfg, err := config.Load("configs/example-node.yaml")
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	fmt.Printf("Target node: %s (%s)\n", cfg.Node.Hostname, cfg.Node.Role)
	fmt.Printf("Location: %s\n", cfg.Node.Location)
	fmt.Printf("Services: %d\n", len(cfg.Services))

	_ = sshutil.NewSSHClient // TODO: remove when provisioner is ready
	fmt.Println("\n✓ Config loaded successfully!")
	fmt.Println("(SSH provisioning not yet implemented)")
}
