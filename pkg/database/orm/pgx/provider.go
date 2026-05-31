package pgx

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5/pgconn"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	ezlog "github.com/flipcloud-ai/ezauth/log"
	ezdb "github.com/flipcloud-ai/ezauth/pkg/database"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
)

func convertToProviderConfig(model *models.ProviderDB) (*ezcfg.ProviderConfig, error) {
	p := &ezcfg.ProviderConfig{}
	err := models.ParseData(model, p)
	if err != nil {
		return nil, err
	}
	return p, nil
}

// ListProviders returns all provider records (including disabled) with pagination.
func (db *PGxDB) ListProviders(ctx context.Context, limit, offset int) ([]*models.ProviderDB, error) {
	return listRecords[models.ProviderDB](ctx, db, limit, offset, "provider_name", "provider")
}

// ScanProviders loads up to size provider configs from the database.
func (db *PGxDB) ScanProviders(ctx context.Context, size int) ([]*ezcfg.ProviderConfig, error) {
	if size == 0 {
		size = 30
	}
	var providers []*models.ProviderDB
	if err := db.WithContext(ctx).Model(&models.ProviderDB{}).Where("enabled = ?", true).Limit(size).Find(&providers).Error; err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "42P01" {
			db.Logger.Error("Provider table doesn't exist")
			return nil, ezdb.ErrNeedInit
		}
		return nil, err
	}
	result := make([]*ezcfg.ProviderConfig, 0, len(providers))
	for _, provider := range providers {
		if provider == nil {
			continue
		}
		p, err := convertToProviderConfig(provider)
		if err != nil {
			db.Logger.Error("Error in converting provider", ezlog.Str("provider", provider.ProviderName), ezlog.Err(err))
			continue
		}
		result = append(result, p)
	}
	return result, nil
}

// GetProvider retrieves a provider config by name from the database.
func (db *PGxDB) GetProvider(ctx context.Context, name string) (*ezcfg.ProviderConfig, error) {
	p, err := getRecord[models.ProviderDB](ctx, db, "provider_name = ?", name, nil, "provider")
	if err != nil {
		return nil, err
	}
	cfg, err := convertToProviderConfig(p)
	if err != nil {
		db.Logger.Error("Error converting provider", ezlog.Str("provider", name), ezlog.Err(err))
		return nil, ezdb.ErrOperation
	}
	return cfg, nil
}

// UpdateProvider updates a provider record in the database.
func (db *PGxDB) UpdateProvider(ctx context.Context, p *models.ProviderDB) error {
	return updateRecord[models.ProviderDB](ctx, db, updateConfig{
		Where: "provider_name = ?",
		Key:   p.ProviderName,
		Omit:  []string{"ProviderName", "Type"},
	}, p, "provider")
}

// DeleteProvider removes a provider record by name from the database.
func (db *PGxDB) DeleteProvider(ctx context.Context, name string) error {
	return deleteRecord[models.ProviderDB](ctx, db, "provider_name = ?", name, "provider")
}

// AddProvider creates a new provider record in the database.
func (db *PGxDB) AddProvider(ctx context.Context, p *models.ProviderDB) error {
	if err := db.WithContext(ctx).Create(p).Error; err != nil {
		return handleCreateError(db, err, "provider")
	}
	db.Logger.Info("Provider added successfully", ezlog.Str("provider", p.ProviderName))
	return nil
}
