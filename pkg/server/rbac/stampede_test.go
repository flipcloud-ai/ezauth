package rbac

import (
	"context"
	"sync"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	ezlog "github.com/flipcloud-ai/ezauth/log"
	"github.com/flipcloud-ai/ezauth/pkg/cache"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/models"
	"github.com/flipcloud-ai/ezauth/pkg/database/orm/pgx"
	testutils "github.com/flipcloud-ai/ezauth/test/utils"
)

// blockingPGxDB embeds *pgx.PGxDB and overrides GetPermission to block until
// releaseCh is closed, simulating a slow database during cancellation tests.
type blockingPGxDB struct {
	*pgx.PGxDB
	releaseCh <-chan struct{}
}

func (b *blockingPGxDB) GetPermission(ctx context.Context, _ string) (*models.Permission, error) {
	select {
	case <-b.releaseCh:
		return nil, context.Canceled
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

var _ = Describe("RBAC stampede protection", func() {
	testLogger, _ := testutils.SetupTestLogger()

	Describe("GetPermission singleflight", func() {
		It("should issue exactly one DB call when N goroutines miss the same key concurrently", func() {
			const goroutines = 20

			mockDB, mockSQL := setupMockDB(testLogger)

			// Expect exactly one SELECT — singleflight deduplicates the rest.
			mockSQL.ExpectQuery(`SELECT \* FROM "rbac_permissions"`).
				WithArgs("auth::user::read", 1).
				WillReturnRows(mockSQL.NewRows(permissionColumns()).
					AddRow(createPermissionRow("auth::user::read", "auth", "user::read", "GET", "/users/", false)...))

			c := cache.NewMemoryCache[string, []byte](10000, CacheTTL)
			ctx := ezlog.ServerContext(context.Background(), testLogger)
			ctrl, err := NewController(ctx, nil, mockDB, c, "/ezauth", "")
			Expect(err).ToNot(HaveOccurred())

			var wg sync.WaitGroup
			ready := make(chan struct{})
			results := make([]*models.Permission, goroutines)
			errs := make([]error, goroutines)

			wg.Add(goroutines)
			for i := range goroutines {
				go func() {
					defer wg.Done()
					<-ready
					results[i], errs[i] = ctrl.GetPermission(context.Background(), "auth::user::read")
				}()
			}
			close(ready)
			wg.Wait()

			for i := range goroutines {
				Expect(errs[i]).ToNot(HaveOccurred(), "goroutine %d failed", i)
				Expect(results[i].Name).To(Equal("auth::user::read"))
			}
			// sqlmock enforces that no unexpected queries were issued.
			Expect(mockSQL.ExpectationsWereMet()).To(Succeed())
		})

		It("should return ctx.Err() when context is cancelled while waiting for flight", func() {
			releaseCh := make(chan struct{})

			// Build a real PGxDB via sqlmock so the interface is fully satisfied,
			// then wrap it with blockingPGxDB which overrides GetPermission.
			realDB, _ := setupMockDB(testLogger)
			blockDB := &blockingPGxDB{PGxDB: realDB, releaseCh: releaseCh}

			c := cache.NewMemoryCache[string, []byte](10000, CacheTTL)

			// Seed the cache with data that fails JSON unmarshal so the first cache
			// check is bypassed and all goroutines reach the singleflight gate.
			_ = c.Set(context.Background(), permissionCacheKey("auth::slow::read"), []byte("not-json"), CacheTTL)

			ctx := ezlog.ServerContext(context.Background(), testLogger)
			ctrl, err := NewController(ctx, nil, blockDB, c, "/ezauth", "")
			Expect(err).ToNot(HaveOccurred())

			cancelCtx, cancel := context.WithCancel(context.Background())

			var wg sync.WaitGroup
			wg.Add(1)
			var callErr error
			go func() {
				defer wg.Done()
				_, callErr = ctrl.GetPermission(cancelCtx, "auth::slow::read")
			}()

			// Give the goroutine time to enter DoChan, then cancel the context.
			time.Sleep(20 * time.Millisecond)
			cancel()
			wg.Wait()

			Expect(callErr).To(MatchError(context.Canceled))

			// Release the in-flight goroutine so the test suite can clean up.
			close(releaseCh)
		})
	})
})
