package pgx

import (
	"context"
	"fmt"

	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

// InsertAuditEvents persists a batch of audit events in a single transaction.
func (db *PGxDB) InsertAuditEvents(ctx context.Context, events []*models.AuditEventDB) error {
	if len(events) == 0 {
		return nil
	}
	if err := db.WithContext(ctx).Create(events).Error; err != nil {
		return fmt.Errorf("%w: insert audit events: %s", ezdb.ErrOperation, err)
	}
	return nil
}

// ListAuditEventsDB returns audit events ordered by timestamp descending.
func (db *PGxDB) ListAuditEventsDB(ctx context.Context, limit, offset int) ([]*models.AuditEventDB, error) {
	var events []*models.AuditEventDB
	if err := db.WithContext(ctx).
		Order("timestamp DESC").
		Limit(limit).Offset(offset).
		Find(&events).Error; err != nil {
		return nil, fmt.Errorf("%w: list audit events: %s", ezdb.ErrOperation, err)
	}
	return events, nil
}
