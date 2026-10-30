package services

import (
	"errors"
	"fmt"

	"github.com/sentinel/siem-backend/internal/database"
	"github.com/sentinel/siem-backend/internal/models"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrForbidden = errors.New("forbidden")
)

// GetVisibleDeviceIDs returns nil if user is admin (full fleet access).
// Otherwise returns slice of device_ids owned or created by user.
func GetVisibleDeviceIDs(user *models.User, store *database.Store) []string {
	if user.Role == "admin" {
		return nil
	}

	allDevs := store.GetAllDevices()
	visible := make([]string, 0)
	for _, d := range allDevs {
		if d.Owner == user.Username || d.CreatedBy == user.Username {
			visible = append(visible, d.DeviceID)
		}
	}
	return visible
}

// VerifyDeviceAccess checks that the device exists and that the user has permission to access it.
func VerifyDeviceAccess(deviceID string, user *models.User, store *database.Store) (*models.Device, error) {
	dev, ok := store.GetDevice(deviceID)
	if !ok {
		return nil, ErrNotFound
	}

	if user.Role == "admin" {
		return dev, nil
	}

	owner := dev.Owner
	if owner == "" {
		owner = dev.CreatedBy
	}
	if owner == "" {
		owner = "admin"
	}

	if owner != user.Username && dev.CreatedBy != user.Username {
		return nil, fmt.Errorf("%w: you do not have permission to access this device", ErrForbidden)
	}

	return dev, nil
}

// RequireNotViewer ensures user is not a read-only viewer/auditor.
func RequireNotViewer(user *models.User, actionName string) error {
	if user.Role == "viewer" {
		return fmt.Errorf("%w: auditor accounts cannot %s (read-only)", ErrForbidden, actionName)
	}
	return nil
}

// RequireAdmin ensures user is a SOC Administrator.
func RequireAdmin(user *models.User, actionName string) error {
	if user.Role != "admin" {
		return fmt.Errorf("%w: only SOC Administrators can %s", ErrForbidden, actionName)
	}
	return nil
}
