package pgx

import (
	"context"
	"time"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

// CreatePAT inserts a new PAT record into the database.
func (db *PGxDB) CreatePAT(ctx context.Context, pat *models.PATDB) error {
	tx := db.WithContext(ctx).Create(pat)
	if tx.Error != nil {
		return handleCreateError(db, tx.Error, pat.TableName())
	}
	return nil
}

// GetPATByHash looks up a PAT by its SHA-256 hash.
func (db *PGxDB) GetPATByHash(ctx context.Context, hash string) (*models.PATDB, error) {
	return getRecord[models.PATDB](ctx, db, "hash = ?", hash, nil, "pat_token")
}

// ListPATs returns all PATs belonging to the given user, ordered by creation time descending.
func (db *PGxDB) ListPATs(ctx context.Context, userID string) ([]*models.PATDB, error) {
	var pats []*models.PATDB
	tx := db.WithContext(ctx).Where("user_id = ?", userID).Order("created_at DESC").Find(&pats)
	if tx.Error != nil {
		db.Logger.Error("error listing PATs", ezlog.Str("user_id", userID), ezlog.Err(tx.Error))
		return nil, ezdb.ErrOperation
	}
	return pats, nil
}

// DeletePAT removes a PAT by its ID, scoped to the owning user.
func (db *PGxDB) DeletePAT(ctx context.Context, id, userID string) error {
	tx := db.WithContext(ctx).Where("id = ? AND user_id = ?", id, userID).Delete(&models.PATDB{})
	if tx.Error != nil {
		db.Logger.Error("error deleting PAT", ezlog.Str("id", id), ezlog.Err(tx.Error))
		return ezdb.ErrOperation
	}
	if tx.RowsAffected == 0 {
		db.Logger.Warn("PAT not found for deletion", ezlog.Str("id", id), ezlog.Str("user_id", userID))
		return ezdb.ErrNoRecord
	}
	return nil
}

// UpdatePATLastUsed updates the last_used_at timestamp for a PAT.
func (db *PGxDB) UpdatePATLastUsed(ctx context.Context, id string) error {
	now := time.Now()
	return updateRecord(ctx, db, updateConfig{
		Where:  "id = ?",
		Key:    id,
		Select: []string{"last_used_at"},
	}, &models.PATDB{LastUsedAt: &now}, "pat_token")
}
