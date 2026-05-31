package pgx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"
	"gorm.io/gorm"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
)

func checkTableExists(db *PGxDB, err error, label string) error {
	e := errors.Unwrap(err)
	if e == nil {
		e = err
	}
	var pgErr *pgconn.PgError
	if errors.As(e, &pgErr) && pgErr.Code == "42P01" {
		db.Logger.Error("table does not exist", ezlog.Str("table", label))
		return ezdb.ErrNeedInit
	}
	return nil
}

func handleCreateError(db *PGxDB, err error, label string) error {
	e := errors.Unwrap(err)
	if e == nil {
		e = err
	}
	var pgErr *pgconn.PgError
	if errors.As(e, &pgErr) {
		switch pgErr.Code {
		case "23505":
			return ezdb.ErrConflict
		case "23502":
			db.Logger.Error("adding with null key: value should not be empty", ezlog.Str("type", label), ezlog.Str("column", pgErr.ColumnName))
			return ezdb.NewDatabaseError(http.StatusBadRequest, fmt.Errorf("%s key should not be empty", pgErr.ColumnName))
		}
	} else {
		if err == gorm.ErrDuplicatedKey {
			return ezdb.ErrConflict
		} else if strings.HasPrefix(err.Error(), "validation error") {
			db.Logger.Error("error adding", ezlog.Str("type", label), ezlog.Err(err))
			return ezdb.NewDatabaseError(http.StatusBadRequest, err)
		}
	}
	return ezdb.ErrOperation
}

func getRecord[T any](ctx context.Context, db *PGxDB, where string, key any, preloads map[string]string, label string) (*T, error) {
	var record T
	tx := db.WithContext(ctx).Where(where, key)
	for assoc, fields := range preloads {
		f := fields
		tx = tx.Preload(assoc, func(db *gorm.DB) *gorm.DB {
			return db.Select(f)
		})
	}
	tx = tx.First(&record)
	if tx.Error != nil {
		if errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			db.Logger.Warn("not found", ezlog.Str("type", label), ezlog.Any("key", key))
			return nil, ezdb.ErrNoRecord
		}
		db.Logger.Error("error getting", ezlog.Str("type", label), ezlog.Any("key", key), ezlog.Err(tx.Error))
		return nil, ezdb.ErrOperation
	}
	return &record, nil
}

func listRecords[T any](ctx context.Context, db *PGxDB, limit, offset int, orderBy, label string) ([]*T, error) {
	if limit == 0 {
		limit = 30
	}
	records := make([]*T, 0, limit)
	tx := db.WithContext(ctx).Model(new(T)).Order(orderBy).Limit(limit).Offset(offset).Find(&records)
	if tx.Error != nil {
		if e := checkTableExists(db, tx.Error, label); e != nil {
			return nil, e
		}
		db.Logger.Error("error listing", ezlog.Str("type", label), ezlog.Err(tx.Error))
		return nil, ezdb.ErrOperation
	}
	return records, nil
}

type updateConfig struct {
	Where     string
	Key       any
	Select    []string
	Omit      []string
	SkipHooks bool
}

func updateRecord[T any](ctx context.Context, db *PGxDB, cfg updateConfig, updates *T, label string) error {
	tx := db.WithContext(ctx)
	if cfg.SkipHooks {
		tx = tx.Session(&gorm.Session{SkipHooks: true})
	}
	tx = tx.Model(new(T)).Where(cfg.Where, cfg.Key)
	if len(cfg.Select) > 0 {
		tx = tx.Select(cfg.Select)
	}
	if len(cfg.Omit) > 0 {
		tx = tx.Omit(cfg.Omit...)
	}
	tx = tx.Updates(updates)
	if tx.Error != nil {
		if strings.HasPrefix(tx.Error.Error(), "validation error") {
			db.Logger.Error("error updating", ezlog.Str("type", label), ezlog.Any("key", cfg.Key), ezlog.Err(tx.Error))
			return ezdb.NewDatabaseError(http.StatusBadRequest, tx.Error)
		} else if tx.Error == gorm.ErrDuplicatedKey {
			return ezdb.ErrConflict
		}
		db.Logger.Error("error updating", ezlog.Str("type", label), ezlog.Any("key", cfg.Key), ezlog.Err(tx.Error))
		return ezdb.ErrOperation
	}
	if tx.RowsAffected == 0 {
		db.Logger.Warn("not found for update", ezlog.Str("type", label), ezlog.Any("key", cfg.Key))
		return ezdb.ErrNoRecord
	}
	return nil
}

func deleteRecord[T any](ctx context.Context, db *PGxDB, where string, key any, label string) error {
	tx := db.WithContext(ctx).Where(where, key).Delete(new(T))
	if tx.Error != nil {
		if !errors.Is(tx.Error, gorm.ErrRecordNotFound) {
			db.Logger.Error("error deleting", ezlog.Str("type", label), ezlog.Any("key", key), ezlog.Err(tx.Error))
			return ezdb.ErrOperation
		}
	}
	if tx.RowsAffected == 0 {
		db.Logger.Warn("not found for deletion", ezlog.Str("type", label), ezlog.Any("key", key))
		return ezdb.ErrNoRecord
	}
	return nil
}
