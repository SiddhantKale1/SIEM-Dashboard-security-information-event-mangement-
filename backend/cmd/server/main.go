package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sentinel/siem-backend/internal/api"
	"github.com/sentinel/siem-backend/internal/config"
	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/services"
)

func main() {
	cfg := config.LoadConfig()

	log.Printf("[*] Initializing High-Performance Go SIEM Server on port %s...", cfg.Port)

	store, err := database.NewStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("[-] Failed to initialize database store: %v", err)
	}

	aiEngine := services.NewAIEngine(store)
	netMgr := services.NewNetworkManager(store)

	netInfo := netMgr.GetLocalNetworkInfo()
	log.Printf("[+] Local Network Discovery: IP=%s Subnet=%s Gateway=%s", netInfo.ServerIP, netInfo.Subnet, netInfo.Gateway)

	router := api.NewRouter(cfg, store, aiEngine, netMgr)

	addr := fmt.Sprintf("0.0.0.0:%s", cfg.Port)
	server := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Server runner
	go func() {
		log.Printf("[🚀] Go SIEM Backend listening on http://%s", addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[-] Server failed: %v", err)
		}
	}()

	// Graceful shutdown listener
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	log.Println("[*] Shutting down Go SIEM Server gracefully...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_ = store.Save()
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("[-] Server forced shutdown error: %v", err)
	}
	log.Println("[+] Go SIEM Server shutdown complete.")
}
