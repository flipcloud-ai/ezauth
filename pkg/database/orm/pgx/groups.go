package pgx

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"gorm.io/gorm"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

// ListGroups returns a paginated list of groups from the database.
func (db *PGxDB) ListGroups(ctx context.Context, limit, offset int) ([]*models.GroupDB, error) {
	return listRecords[models.GroupDB](ctx, db, limit, offset, "name", "group")
}

// GetGroup retrieves a group by name, preloading associated roles and users.
func (db *PGxDB) GetGroup(ctx context.Context, name string) (*models.GroupDB, error) {
	return getRecord[models.GroupDB](ctx, db, "name = ?", name, map[string]string{
		"Roles": "ID,Name",
		"Users": "ID,Username",
	}, "group")
}

// AddGroup creates a new group in the database.
func (db *PGxDB) AddGroup(ctx context.Context, g *models.GroupDB) error {
	if err := db.WithContext(ctx).Create(g).Error; err != nil {
		return handleCreateError(db, err, "group")
	}
	return nil
}

// UpdateGroup updates a group record identified by name.
func (db *PGxDB) UpdateGroup(ctx context.Context, name string, g *models.GroupDB) error {
	return updateRecord[models.GroupDB](ctx, db, updateConfig{
		Where:  "name = ?",
		Key:    name,
		Select: []string{"GroupName"},
	}, g, "group")
}

// DeleteGroup removes a group by name from the database.
func (db *PGxDB) DeleteGroup(ctx context.Context, name string) error {
	return deleteRecord[models.GroupDB](ctx, db, "name = ?", name, "group")
}

// AddUserToGroup adds one or more users to a group within a transaction.
func (db *PGxDB) AddUserToGroup(ctx context.Context, groupName string, userIDs []string) error {
	return db.WithContext(ctx).Session(&gorm.Session{SkipHooks: true}).Transaction(func(tx *gorm.DB) error { //nolint:wrapcheck // returns own sentinel errors
		var group models.GroupDB
		if err := tx.First(&group, "name = ?", groupName).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				db.Logger.Warn("group not found", ezlog.Str("group", groupName))
				return ezdb.NewDatabaseError(http.StatusNotFound, fmt.Errorf("group %s not found", groupName))
			}
			db.Logger.Error("error in finding group", ezlog.Str("group", groupName), ezlog.Err(err))
			return ezdb.ErrOperation
		}

		var users []*models.UserDB
		if err := tx.Where("id IN ?", userIDs).Find(&users).Error; err != nil {
			db.Logger.Error("error in finding users", ezlog.Any("user_ids", userIDs), ezlog.Err(err))
			return ezdb.ErrOperation
		}
		if len(users) != len(userIDs) {
			found := make(map[string]bool, len(users))
			for _, u := range users {
				found[u.ID.String()] = true
			}
			for _, id := range userIDs {
				if !found[id] {
					db.Logger.Warn("user not found", ezlog.Str("user_id", id))
					return ezdb.NewDatabaseError(http.StatusBadRequest, fmt.Errorf("user %s not found", id))
				}
			}
		}

		if err := tx.Model(&group).Association("Users").Append(users); err != nil {
			db.Logger.Error("error in adding users to group", ezlog.Str("group", groupName), ezlog.Err(err))
			return ezdb.ErrOperation
		}
		return nil
	})
}

// RemoveUserFromGroup removes one or more users from a group within a transaction.
func (db *PGxDB) RemoveUserFromGroup(ctx context.Context, groupName string, userIDs []string) error {
	return db.WithContext(ctx).Session(&gorm.Session{SkipHooks: true}).Transaction(func(tx *gorm.DB) error { //nolint:wrapcheck // returns own sentinel errors
		var group models.GroupDB
		if err := tx.First(&group, "name = ?", groupName).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				db.Logger.Warn("group not found", ezlog.Str("group", groupName))
				return ezdb.NewDatabaseError(http.StatusNotFound, fmt.Errorf("group %s not found", groupName))
			}
			db.Logger.Error("error in finding group", ezlog.Str("group", groupName), ezlog.Err(err))
			return ezdb.ErrOperation
		}

		var users []*models.UserDB
		if err := tx.Where("id IN ?", userIDs).Find(&users).Error; err != nil {
			db.Logger.Error("error in finding users", ezlog.Any("user_ids", userIDs), ezlog.Err(err))
			return ezdb.ErrOperation
		}
		if len(users) != len(userIDs) {
			found := make(map[string]bool, len(users))
			for _, u := range users {
				found[u.ID.String()] = true
			}
			for _, id := range userIDs {
				if !found[id] {
					db.Logger.Warn("user not found", ezlog.Str("user_id", id))
					return ezdb.NewDatabaseError(http.StatusBadRequest, fmt.Errorf("user %s not found", id))
				}
			}
		}

		if err := tx.Model(&group).Association("Users").Delete(users); err != nil {
			db.Logger.Error("error in removing users from group", ezlog.Str("group", groupName), ezlog.Err(err))
			return ezdb.ErrOperation
		}
		return nil
	})
}
