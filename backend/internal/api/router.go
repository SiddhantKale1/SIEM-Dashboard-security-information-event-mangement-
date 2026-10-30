package api

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/sentinel/siem-backend/internal/config"
	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/services"
)

func NewRouter(
	cfg *config.Config,
	store *database.Store,
	aiEngine *services.AIEngine,
	netMgr *services.NetworkManager,
) http.Handler {
	r := chi.NewRouter()

	// Base middlewares
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)

	// Cross-Origin Resource Sharing (CORS) configured for all local & enterprise origins
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// Handlers
	authHandler := NewAuthHandler(store)
	agentHandler := NewAgentHandler(store, aiEngine, netMgr)
	devicesHandler := NewDevicesHandler(store)
	enrollmentHandler := NewEnrollmentHandler(store, cfg, netMgr)
	logsHandler := NewLogsHandler(store)
	anomaliesHandler := NewAnomaliesHandler(store, aiEngine)
	networkHandler := NewNetworkHandler(store, netMgr)

	// Health check endpoint
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"engine":  "golang-enterprise-siem",
			"runtime": "go",
		})
	})

	r.Route("/api/v1", func(v1 chi.Router) {
		// Public Auth
		v1.Post("/auth/login", authHandler.Login)
		v1.Post("/auth/register", authHandler.Register)

		// Authenticated User Auth
		v1.Group(func(userAuth chi.Router) {
			userAuth.Use(authHandler.AuthUserMiddleware)
			userAuth.Get("/auth/me", authHandler.Me)
			userAuth.Post("/auth/change-password", authHandler.ChangePassword)

			// Devices
			userAuth.Get("/devices/{device_id}", devicesHandler.GetDevice)
			userAuth.Get("/devices/{device_id}/metrics", devicesHandler.GetMetrics)
			userAuth.Post("/devices/{device_id}/isolate", devicesHandler.IsolateDevice)
			userAuth.Post("/devices/{device_id}/restore", devicesHandler.RestoreDevice)
			userAuth.Delete("/devices/{device_id}", devicesHandler.DeleteDevice)
			userAuth.Get("/devices/{device_id}/events", devicesHandler.GetDeviceEvents)
			userAuth.Get("/devices/{device_id}/system-logs", devicesHandler.GetDeviceSystemLogs)
			userAuth.Get("/devices/{device_id}/network-logs", devicesHandler.GetDeviceNetworkLogs)
			userAuth.Get("/devices/{device_id}/processes", devicesHandler.GetProcesses)

			// Enrollment Tokens Management
			userAuth.Post("/enrollment/token", enrollmentHandler.CreateToken)
			userAuth.Get("/enrollment/tokens", enrollmentHandler.ListTokens)
			userAuth.Delete("/enrollment/tokens/{token_id}", enrollmentHandler.RevokeToken)

			// Logs & Metrics telemetry
			userAuth.Get("/logs/stats", logsHandler.GetStats)
			userAuth.Get("/logs/hourly", logsHandler.GetHourly)
			userAuth.Get("/logs", logsHandler.GetLogs)

			// Anomalies & Threat Intelligence
			userAuth.Get("/anomalies/stats", anomaliesHandler.GetStats)
			userAuth.Get("/anomalies", anomaliesHandler.ListAnomalies)
			userAuth.Get("/anomalies/{anomaly_id}", anomaliesHandler.GetAnomaly)
			userAuth.Post("/anomalies/{anomaly_id}/resolve", anomaliesHandler.ResolveAnomaly)

			// Network Discovery & Sessions
			userAuth.Get("/network/traffic", networkHandler.GetTraffic)
			userAuth.Get("/network/active", networkHandler.GetActiveDevices)
			userAuth.Get("/network/history", networkHandler.GetHistory)
		})

		// Public Agent Enrollment & Installer Delivery
		v1.Post("/enrollment/register", enrollmentHandler.RegisterDevice)
		v1.Get("/enrollment/install.sh", enrollmentHandler.ServeLinuxInstaller)
		v1.Head("/enrollment/install.sh", enrollmentHandler.ServeLinuxInstaller)
		v1.Get("/enrollment/install.ps1", enrollmentHandler.ServeWindowsInstaller)
		v1.Head("/enrollment/install.ps1", enrollmentHandler.ServeWindowsInstaller)
		v1.Get("/enrollment/agent.py", enrollmentHandler.ServeAgentPy)
		v1.Head("/enrollment/agent.py", enrollmentHandler.ServeAgentPy)

		// Authenticated Agent Telemetry Ingestion (with isolation quarantine check)
		v1.Group(func(agentAuth chi.Router) {
			agentAuth.Use(authHandler.AuthDeviceMiddleware)
			agentAuth.Post("/agent/heartbeat", agentHandler.Heartbeat)
			agentAuth.Post("/agent/logs", agentHandler.ReceiveLogs)
			agentAuth.Post("/agent/metrics", agentHandler.ReceiveMetrics)
			agentAuth.Post("/agent/processes", agentHandler.ReceiveProcesses)
		})
	})

	return r
}
