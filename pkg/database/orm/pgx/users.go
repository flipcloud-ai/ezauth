package pgx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezapi "github.com/flipcloud-ai/ezauth/pkg/apis"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	"github.com/flipcloud-ai/ezauth/pkg/utils"
)

// dummyHash is a pre-computed bcrypt hash used to equalise response time when a
// user is not found, preventing username enumeration via timing side-channels.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)

// ListUsers returns a paginated list of users with their group memberships.
func (db *PGxDB) ListUsers(ctx context.Context, limit, offset int) ([]*models.UserDB, error) {
	if limit == 0 {
		limit = 30
	}
	records := make([]*models.UserDB, 0, limit)
	tx := db.WithContext(ctx).
		Preload("Groups", func(db *gorm.DB) *gorm.DB { return db.Select("id, name") }).
		Order("username").Limit(limit).Offset(offset).Find(&records)
	if tx.Error != nil {
		if e := checkTableExists(db, tx.Error, "user"); e != nil {
			return nil, e
		}
		db.Logger.Error("error listing", ezlog.Str("type", "user"), ezlog.Err(tx.Error))
		return nil, ezdb.ErrOperation
	}
	return records, nil
}

// GetUser retrieves the user with the given ID.
func (db *PGxDB) GetUser(ctx context.Context, id string) (*models.UserDB, error) {
	u, err := getRecord[models.UserDB](ctx, db, "id = ?", id, map[string]string{
		"Roles":  "ID,Name",
		"Groups": "ID,Name",
	}, "user")
	if err != nil {
		return nil, err
	}
	u.Password = ""
	u.PasswordSalt = ""
	return u, nil
}

// UpdateUser updates the user record identified by ID, email, or mobile number.
func (db *PGxDB) UpdateUser(ctx context.Context, u *models.UserDB) error {
	tx := db.WithContext(ctx).Model(&models.UserDB{})
	hasCondition := false
	if idStr := u.ID.String(); u.ID != uuid.Nil && idStr != "" {
		// Use ID as the authoritative identifier when available.
		tx = tx.Where("id = ?", idStr)
		hasCondition = true
	} else if u.MobileNumber != "" {
		// Fall back to mobile number only if ID is not provided.
		tx = tx.Where("mobile_number = ?", u.MobileNumber)
		hasCondition = true
	} else if u.Email != "" {
		// Fall back to email only if neither ID nor mobile number is provided.
		tx = tx.Where("email = ?", u.Email)
		hasCondition = true
	}
	if !hasCondition {
		db.Logger.Error("no identifying fields provided for UpdateUser")
		return ezdb.ErrOperation
	}
	tx = tx.Omit("Password", "PasswordSalt", "CreatedAt", "LastLogin", "PasswordUpdatedAt", "UpdatedAt", "ID", "Roles", "Groups").Updates(u)
	if tx.Error != nil {
		if strings.HasPrefix(tx.Error.Error(), "validation error") {
			db.Logger.Error("Error in updating user", ezlog.Err(tx.Error))
			return ezdb.NewDatabaseError(http.StatusBadRequest, tx.Error)
		} else if !errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			db.Logger.Error("error in updating user", ezlog.Err(tx.Error))
			return ezdb.ErrOperation
		}
	}
	if tx.RowsAffected == 0 {
		db.Logger.Warn("user not found")
		return ezdb.ErrNoRecord
	}
	return nil
}

// DeleteUser removes the user with the given ID.
func (db *PGxDB) DeleteUser(ctx context.Context, id string) error {
	return deleteRecord[models.UserDB](ctx, db, "id = ?", id, "user")
}

// AddUser creates a new user record, hashing the password before storage.
func (db *PGxDB) AddUser(ctx context.Context, u *models.UserDB) error {
	password := u.Password
	hashedPassword, salt, err := utils.GeneratePwd(password)
	if err != nil {
		if errors.Is(err, utils.ErrInvalidPassword) {
			return ezdb.NewDatabaseError(http.StatusBadRequest, err)
		}
		return ezdb.ErrOperation
	}
	u.Password = string(hashedPassword)
	u.PasswordSalt = salt

	if err := db.WithContext(ctx).Omit("LastLogin", "PasswordUpdatedAt", "UpdatedAt", "CreatedAt").Create(u).Error; err != nil {
		return handleCreateError(db, err, "user")
	}
	return nil
}

// ResetPassword replaces the password for the user with the given ID.
// The operation runs in a transaction with SELECT ... FOR UPDATE to prevent
// TOCTOU races with concurrent logins or password resets on the same user.
func (db *PGxDB) ResetPassword(ctx context.Context, id string, newPassword string) error {
	// Hash outside the transaction to minimise lock duration.
	hashedPassword, salt, err := utils.GeneratePwd(newPassword)
	if err != nil {
		if errors.Is(err, utils.ErrInvalidPassword) {
			db.Logger.Warn("invalid new password for user", ezlog.Str("user_id", id), ezlog.Err(err))
			return ezdb.NewDatabaseError(http.StatusBadRequest, fmt.Errorf("invalid password"))
		}
		db.Logger.Error("failed to hash password for user", ezlog.Str("user_id", id), ezlog.Err(err))
		return ezdb.ErrOperation
	}

	if err := db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var user models.UserDB
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Where("id = ?", id).
			First(&user).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				db.Logger.Warn("user not found for password reset", ezlog.Str("user_id", id))
				return ezdb.ErrNoRecord
			}
			db.Logger.Error("error getting user for password reset", ezlog.Str("user_id", id), ezlog.Err(err))
			return ezdb.ErrOperation
		}

		result := tx.Model(&user).Updates(map[string]any{
			"Password":          string(hashedPassword),
			"PasswordSalt":      salt,
			"PasswordUpdatedAt": time.Now(),
		})
		if result.Error != nil {
			db.Logger.Error("error updating password", ezlog.Str("user_id", id), ezlog.Err(result.Error))
			return ezdb.ErrOperation
		}
		if result.RowsAffected == 0 {
			db.Logger.Warn("user not found, skip password update", ezlog.Str("user_id", id))
			return ezdb.ErrNoRecord
		}
		return nil
	}); err != nil {
		if errors.Is(err, ezdb.ErrNoRecord) || errors.Is(err, ezdb.ErrOperation) {
			return err //nolint:wrapcheck // sentinel errors must pass through unwrapped for errors.Is comparisons
		}
		return fmt.Errorf("reset password transaction: %w", err)
	}
	return nil
}

// UserLogin authenticates a user by username or email and password, returning their profile on success.
func (db *PGxDB) UserLogin(ctx context.Context, usernameOrEmail string, password string) (*ezapi.Profile, error) {
	var user models.UserDB
	result := db.WithContext(ctx).
		Where("username = ? OR email = ?", usernameOrEmail, usernameOrEmail).
		Select("ID", "Username", "Password", "PasswordSalt", "FirstName", "LastName", "Email").
		First(&user)
	if result.Error != nil {
		if errors.Is(result.Error, gorm.ErrRecordNotFound) {
			db.Logger.Warn("user not found", ezlog.Str("username", usernameOrEmail))
			// Perform a dummy bcrypt comparison to equalise response time with the
			// "wrong password" path, preventing username enumeration via timing.
			_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
			return nil, ezdb.ErrNoRecord
		}
		db.Logger.Error("error in getting user", ezlog.Err(result.Error))
		return nil, ezdb.ErrOperation
	}

	combined := user.PasswordSalt + password
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(combined)); err != nil {
		db.Logger.Warn("invalid password for user", ezlog.Str("username", usernameOrEmail))
		return nil, ezdb.ErrInvalidCreds
	}

	if err := db.WithContext(ctx).Model(&user).Update("LastLogin", time.Now()).Error; err != nil {
		db.Logger.Warn("failed to update last_login, continuing", ezlog.Str("user", user.Username), ezlog.Err(err))
	}

	// Subject is the user's UUID so RBAC permission lookups (keyed by user ID) resolve correctly.
	return &ezapi.Profile{
		User:      user.Username,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		Email:     user.Email,
		Subject:   user.ID.String(),
	}, nil
}
