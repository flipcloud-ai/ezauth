package bootstrap

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gorm.io/gorm"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	"github.com/flipcloud-ai/ezauth/pkg/utils"
)

const defaultRootUsername = "root"

// Config holds bootstrap parameters.
type Config struct {
	SecretFile       string
	SystemAdminGroup string
}

// resolveDefaults fills in zero-value fields with their defaults.
func (c Config) resolveDefaults() Config {
	if c.SecretFile == "" {
		c.SecretFile = "/opt/ezauth/secrets/root_secret"
	}
	if c.SystemAdminGroup == "" {
		c.SystemAdminGroup = "system-admins"
	}
	return c
}

// Bootstrap idempotently ensures a root user and system admin group exist in
// the database. All failures are logged as warnings; the caller always
// continues.
func Bootstrap(ctx context.Context, db database.DatabaseInterface, logger ezlog.Logger, cfg Config) {
	if db == nil {
		return
	}

	cfg = cfg.resolveDefaults()

	username, password, err := loadOrCreateBootstrapSecret(logger, cfg.SecretFile)
	if err != nil {
		logger.Warn("bootstrap: failed to load or create root secret, skipping",
			ezlog.Err(err))
		return
	}

	rootUserID, created, err := ensureRootUser(ctx, db, username, password)
	if err != nil {
		logger.Warn("bootstrap: could not ensure root user",
			ezlog.Str("user", username), ezlog.Err(err))
		return
	}
	if created {
		logger.Info("bootstrap: created root user", ezlog.Str("user", username))
	} else {
		logger.Debug("bootstrap: root user already exists", ezlog.Str("user", username))
	}

	groupCreated, err := ensureSystemAdminGroup(ctx, db, cfg.SystemAdminGroup)
	if err != nil {
		logger.Warn("bootstrap: could not ensure system admin group",
			ezlog.Str("group", cfg.SystemAdminGroup), ezlog.Err(err))
		return
	}
	if groupCreated {
		logger.Info("bootstrap: created system admin group", ezlog.Str("group", cfg.SystemAdminGroup))
	} else {
		logger.Debug("bootstrap: system admin group already exists", ezlog.Str("group", cfg.SystemAdminGroup))
	}

	if err := ensureGroupMembership(ctx, db, logger, cfg.SystemAdminGroup, rootUserID); err != nil {
		logger.Warn("bootstrap: could not add root to system admin group",
			ezlog.Str("user", username), ezlog.Str("group", cfg.SystemAdminGroup), ezlog.Err(err))
		return
	}

	logger.Info("bootstrap: completed successfully",
		ezlog.Str("root_user", username),
		ezlog.Str("admin_group", cfg.SystemAdminGroup))
}

// loadOrCreateBootstrapSecret reads or generates a base64-encoded
// "user:password" secret at path. Creates a random password on first run
// and writes it back to the file.
func loadOrCreateBootstrapSecret(logger ezlog.Logger, path string) (string, string, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is provided by caller from config
	switch {
	case err == nil:
		trimmed := strings.TrimSpace(string(data))
		if trimmed != "" {
			// Try base64-encoded user:password (written by this function or cmd/bootstrap --password).
			if decoded, decErr := base64.StdEncoding.DecodeString(trimmed); decErr == nil {
				if user, pass, ok := strings.Cut(string(decoded), ":"); ok && user != "" && pass != "" {
					return user, pass, nil
				}
			}
			// Fall back to plain-text user:password (e.g. mounted from a Kubernetes Secret via stringData).
			user, pass, ok := strings.Cut(trimmed, ":")
			if !ok || user == "" || pass == "" {
				return "", "", fmt.Errorf("bootstrap secret file %s must contain base64-encoded or plain-text <user>:<password>", path)
			}
			return user, pass, nil
		}
	case errors.Is(err, os.ErrNotExist):
		// fall through to generation
	default:
		return "", "", fmt.Errorf("failed to read bootstrap secret file %s: %w", path, err)
	}

	password, genErr := utils.GeneratePassword()
	if genErr != nil {
		return "", "", fmt.Errorf("failed to generate bootstrap password: %w", genErr)
	}
	username := defaultRootUsername
	encoded := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if mkdirErr := os.MkdirAll(dir, 0o700); mkdirErr != nil {
			return "", "", fmt.Errorf("failed to create bootstrap secret directory %s: %w", dir, mkdirErr)
		}
	}
	if writeErr := os.WriteFile(path, []byte(encoded+"\n"), 0o600); writeErr != nil {
		return "", "", fmt.Errorf("failed to write bootstrap secret file %s: %w", path, writeErr)
	}
	logger.Warn("bootstrap: generated root credentials written to secret file",
		ezlog.Str("path", path))
	return username, password, nil
}

// ensureRootUser checks if a user with the given username already exists; if
// not, it creates one bypassing BeforeCreate hooks. Returns the user UUID,
// whether the user was newly created, and any error.
func ensureRootUser(ctx context.Context, db database.DatabaseInterface, username, password string) (string, bool, error) {
	var existing models.UserDB
	err := db.Manager().WithContext(ctx).
		Select("id").
		Where("username = ?", username).
		First(&existing).Error
	if err == nil {
		return existing.ID.String(), false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return "", false, fmt.Errorf("checking for existing user %s: %w", username, err)
	}

	hashedPassword, salt, err := utils.GeneratePwd(password)
	if err != nil {
		return "", false, fmt.Errorf("hashing root password: %w", err)
	}

	admin := models.UserDB{
		Username:     username,
		Password:     string(hashedPassword),
		PasswordSalt: salt,
		Email:        username + "@localhost",
		BirthDate:    time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC),
		Active:       true,
		Address:      models.AddressDB{Country: "US"},
	}

	err = db.Manager().WithContext(ctx).
		Session(&gorm.Session{SkipHooks: true}).
		Omit("LastLogin", "PasswordUpdatedAt", "UpdatedAt", "CreatedAt").
		Create(&admin).Error
	if err != nil {
		return "", false, fmt.Errorf("creating root user: %w", err)
	}
	return admin.ID.String(), true, nil
}

// ensureSystemAdminGroup checks if the group exists; if not, creates it.
// Returns whether the group was newly created.
func ensureSystemAdminGroup(ctx context.Context, db database.DatabaseInterface, groupName string) (bool, error) {
	var existing models.GroupDB
	err := db.Manager().WithContext(ctx).
		Where("name = ?", groupName).
		First(&existing).Error
	if err == nil {
		return false, nil
	}
	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return false, fmt.Errorf("checking for existing group %s: %w", groupName, err)
	}

	g := &models.GroupDB{GroupName: groupName}
	if err := db.AddGroup(ctx, g); err != nil {
		return false, fmt.Errorf("creating system admin group %s: %w", groupName, err)
	}
	return true, nil
}

// ensureGroupMembership adds rootUserID to groupName if they are not already a
// member.
func ensureGroupMembership(ctx context.Context, db database.DatabaseInterface, logger ezlog.Logger, groupName, userID string) error {
	var group models.GroupDB
	err := db.Manager().WithContext(ctx).
		Preload("Users", "id = ?", userID).
		Where("name = ?", groupName).
		First(&group).Error
	if err != nil {
		return fmt.Errorf("fetching group %s: %w", groupName, err)
	}
	if len(group.Users) > 0 {
		logger.Debug("bootstrap: root already in system admin group",
			ezlog.Str("group", groupName))
		return nil
	}
	if err := db.AddUserToGroup(ctx, groupName, []string{userID}); err != nil {
		return fmt.Errorf("adding root to group %s: %w", groupName, err)
	}
	logger.Info("bootstrap: added root to system admin group", ezlog.Str("group", groupName))
	return nil
}
