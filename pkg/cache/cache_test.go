package cache

import (
	"context"
	"encoding/binary"
	"fmt"
	"hash/maphash"
	"strconv"
	"sync"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
	log "github.com/flipcloud-ai/ezauth/log"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

// sharedCacheTests runs the shared Cache interface conformance tests against any
// Cache[string, string] implementation. Each implementation's Describe block should
// call this with a factory that returns a fresh cache instance.
// Set sleepTTL to false for stores (like miniredis) that don't expire on wall-clock time.
func sharedCacheTests(newCache func() Cache[string, string], sleepTTL ...bool) {
	runTTL := len(sleepTTL) == 0 || sleepTTL[0]
	It("should set and get a value", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", "v1", time.Minute)).To(Succeed())
		val, err := c.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("v1"))
	})

	It("should return ErrNotFound for missing key", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		_, err := c.Get(context.Background(), "missing")
		Expect(err).To(MatchError(ErrNotFound))
	})

	It("should delete a key", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", "v1", time.Minute)).To(Succeed())
		Expect(c.Del(context.Background(), "k1")).To(Succeed())
		_, err := c.Get(context.Background(), "k1")
		Expect(err).To(MatchError(ErrNotFound))
	})

	It("should delete a non-existent key without error", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		Expect(c.Del(context.Background(), "nope")).To(Succeed())
	})

	It("should report Has correctly", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		Expect(c.Has(context.Background(), "k1")).To(BeFalse())
		Expect(c.Set(context.Background(), "k1", "v1", time.Minute)).To(Succeed())
		Expect(c.Has(context.Background(), "k1")).To(BeTrue())
	})

	It("should report Len correctly", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		Expect(c.Len(context.Background())).To(Equal(0))
		Expect(c.Set(context.Background(), "a", "1", time.Minute)).To(Succeed())
		Expect(c.Set(context.Background(), "b", "2", time.Minute)).To(Succeed())
		Expect(c.Len(context.Background())).To(Equal(2))
	})

	It("should flush all entries", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "a", "1", time.Minute)).To(Succeed())
		Expect(c.Set(context.Background(), "b", "2", time.Minute)).To(Succeed())
		Expect(c.Flush(context.Background())).To(Succeed())
		Expect(c.Len(context.Background())).To(Equal(0))
		Expect(c.Has(context.Background(), "a")).To(BeFalse())
	})

	It("should update an existing key", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", "v1", time.Minute)).To(Succeed())
		Expect(c.Set(context.Background(), "k1", "v2", time.Minute)).To(Succeed())
		val, err := c.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("v2"))
	})

	if runTTL {
		It("should expire entries after TTL", func() {
			c := newCache()
			defer func() { _ = c.Close() }()

			Expect(c.Set(context.Background(), "k1", "v1", 50*time.Millisecond)).To(Succeed())
			time.Sleep(100 * time.Millisecond)
			_, err := c.Get(context.Background(), "k1")
			Expect(err).To(MatchError(ErrNotFound))
		})
	}

	It("should be safe for concurrent access", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		var wg sync.WaitGroup
		for range 100 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				key := "k"
				Expect(c.Set(context.Background(), key, "v", time.Minute)).To(Succeed())
				_, _ = c.Get(context.Background(), key)
				c.Has(context.Background(), key)
				c.Len(context.Background())
			}()
		}
		wg.Wait()
	})
}

var _ = Describe("MemoryCache", func() {
	sharedCacheTests(func() Cache[string, string] {
		return NewMemoryCache[string, string](100, time.Minute)
	})

	It("should evict entries when capacity is exceeded", func() {
		// Total capacity 64 across 16 shards = 4 per shard.
		// Inserting 200 unique keys forces eviction.
		c := NewMemoryCache[string, string](64, time.Minute)
		defer func() { _ = c.Close() }()

		for i := 0; i < 200; i++ {
			Expect(c.Set(context.Background(), strconv.Itoa(i), "v", 0)).To(Succeed())
		}

		// Per-shard rounding may allow slightly more than the requested size
		// (e.g. 64/16 = 4 per shard exactly, so total = 64 here).
		Expect(c.Len(context.Background())).To(BeNumerically("<=", 64))
		// And there should be fewer than what we inserted.
		Expect(c.Len(context.Background())).To(BeNumerically("<", 200))
	})

	It("should honor an explicit shard count", func() {
		// With 1 shard, size=10 gives a single LRU of capacity 10.
		c := NewMemoryCacheWithShards[string, string](10, 1, time.Minute)
		defer func() { _ = c.Close() }()

		for i := 0; i < 20; i++ {
			Expect(c.Set(context.Background(), strconv.Itoa(i), "v", 0)).To(Succeed())
		}
		Expect(c.Len(context.Background())).To(Equal(10))
	})

	It("should use default TTL when per-key TTL is 0", func() {
		c := NewMemoryCache[string, string](100, 50*time.Millisecond)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", "v1", 0)).To(Succeed())
		time.Sleep(100 * time.Millisecond)
		_, err := c.Get(context.Background(), "k1")
		Expect(err).To(MatchError(ErrNotFound))
	})

	It("should not expire when default TTL is 0", func() {
		c := NewMemoryCache[string, string](100, 0)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", "v1", 0)).To(Succeed())
		time.Sleep(50 * time.Millisecond)
		val, err := c.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("v1"))
	})

	// With shards=1, per-shard capacity equals total size, so all entries
	// fit deterministically regardless of hash distribution.
	It("preserves all entries with shards=1 and size == inserted count", func() {
		for trial := 0; trial < 50; trial++ {
			c := NewMemoryCacheWithShards[string, string](10, 1, time.Minute)
			keys := make([]string, 10)
			for i := 0; i < 10; i++ {
				keys[i] = fmt.Sprintf("k-%d-%d", trial, i)
				Expect(c.Set(context.Background(), keys[i], keys[i], 0)).To(Succeed())
			}
			for _, k := range keys {
				v, err := c.Get(context.Background(), k)
				Expect(err).To(BeNil(), "trial %d key %q", trial, k)
				Expect(v).To(Equal(k))
			}
			_ = c.Close()
		}
	})

	// Regression table: sizes small enough that the shard-collapse path
	// forces n=1, so the cache becomes a pure LRU that must not drop any of
	// the `size` inserted keys regardless of hash distribution. For default
	// shards=16, collapse reaches n=1 whenever size < 32 (since at n=2,
	// size/2 < minPerShard=16 still holds). Tests at shards=1 are a
	// sanity anchor — the invariant must hold there trivially.
	DescribeTable("preserves all entries when collapse forces a single shard",
		func(size, shards int) {
			for trial := 0; trial < 30; trial++ {
				c := NewMemoryCacheWithShards[string, string](size, shards, time.Minute)
				keys := make([]string, size)
				for i := 0; i < size; i++ {
					keys[i] = fmt.Sprintf("k-%d-%d-%d-%d", size, shards, trial, i)
					Expect(c.Set(context.Background(), keys[i], keys[i], 0)).To(Succeed())
				}
				for _, k := range keys {
					v, err := c.Get(context.Background(), k)
					Expect(err).To(BeNil(),
						"size=%d shards=%d trial=%d key=%q", size, shards, trial, k)
					Expect(v).To(Equal(k))
				}
				_ = c.Close()
			}
		},
		// Small sizes at default shards — collapse must push n down to 1.
		Entry("size=1 default shards", 1, DefaultMemoryShards),
		Entry("size=2 default shards", 2, DefaultMemoryShards),
		Entry("size=10 default shards (the original 12%-flake case)", 10, DefaultMemoryShards),
		Entry("size=15 default shards", 15, DefaultMemoryShards),
		Entry("size=16 default shards (at minPerShard)", 16, DefaultMemoryShards),
		Entry("size=31 default shards (just below collapse boundary)", 31, DefaultMemoryShards),
		// Non-pow2 shard counts — nextPow2 rounds up, then collapse runs.
		Entry("size=10 shards=3 (non-pow2, collapses)", 10, 3),
		Entry("size=10 shards=7 (non-pow2, collapses)", 10, 7),
		// Degenerate shard counts must fall back to default and still work.
		Entry("size=10 shards=0 (fallback to default)", 10, 0),
		Entry("size=10 shards=-5 (fallback to default)", 10, -5),
		// shards=1 is the pure-LRU anchor and must work at any size.
		Entry("size=1 shards=1", 1, 1),
		Entry("size=100 shards=1", 100, 1),
		Entry("size=1024 shards=1", 1024, 1),
	)

	// For sizes large enough that the collapse no longer reduces shards to
	// 1, the cache makes a weaker promise: total capacity >= size (modulo
	// per-shard ceiling rounding) but hash collisions can still cause some
	// entries to evict each other. Verify the capacity-bound invariant.
	DescribeTable("respects total-capacity bounds for non-collapsed configs",
		func(size, shards int) {
			c := NewMemoryCacheWithShards[string, string](size, shards, time.Minute)
			defer func() { _ = c.Close() }()
			for i := 0; i < size*4; i++ {
				Expect(c.Set(context.Background(), fmt.Sprintf("k-%d", i), "v", 0)).To(Succeed())
			}
			// Len must never exceed the effective total capacity. With
			// ceiling rounding the ceiling is `ceil(size/n)*n`, bounded
			// above by size + n. Use a loose 2x bound for safety.
			Expect(c.Len(context.Background())).To(BeNumerically("<=", size*2),
				"size=%d shards=%d len=%d exceeds 2x size", size, shards, c.Len(context.Background()))
		},
		Entry("size=128 shards=16", 128, 16),
		Entry("size=100 shards=7 (non-pow2 shards)", 100, 7),
		Entry("size=1024 default shards", 1024, DefaultMemoryShards),
		Entry("size=1024 shards=32", 1024, 32),
	)

	It("falls back to default size when size <= 0", func() {
		c := NewMemoryCache[string, string](0, time.Minute)
		defer func() { _ = c.Close() }()
		// Insert 4x the default size to force eviction and confirm the
		// fallback produced a finite-capacity cache (not an unbounded map).
		for i := 0; i < 4096; i++ {
			Expect(c.Set(context.Background(), strconv.Itoa(i), "v", 0)).To(Succeed())
		}
		Expect(c.Len(context.Background())).To(BeNumerically("<=", 2048),
			"default fallback (size=1024) must bound Len; got %d", c.Len(context.Background()))
	})

	It("evicts LRU within a single shard when its capacity is exceeded", func() {
		// shards=1 gives a pure LRU of capacity 3.
		c := NewMemoryCacheWithShards[string, string](3, 1, time.Minute)
		defer func() { _ = c.Close() }()
		Expect(c.Set(context.Background(), "a", "1", 0)).To(Succeed())
		Expect(c.Set(context.Background(), "b", "2", 0)).To(Succeed())
		Expect(c.Set(context.Background(), "c", "3", 0)).To(Succeed())
		Expect(c.Set(context.Background(), "d", "4", 0)).To(Succeed()) // evicts "a"
		_, err := c.Get(context.Background(), "a")
		Expect(err).To(MatchError(ErrNotFound))
		for _, k := range []string{"b", "c", "d"} {
			v, err := c.Get(context.Background(), k)
			Expect(err).ToNot(HaveOccurred())
			Expect(v).NotTo(BeEmpty(), "key %q should still exist", k)
		}
	})
})

var _ = Describe("MemoryCache sweeper", func() {
	It("removes expired entries via background sweep", func() {
		shard := newMemoryShard[string, string](100, time.Minute)
		c := &MemoryCache[string, string]{
			shards:        []*memoryShard[string, string]{shard},
			mask:          0,
			seed:          maphash.MakeSeed(),
			stopCh:        make(chan struct{}),
			doneCh:        make(chan struct{}),
			sweepInterval: 10 * time.Millisecond,
		}
		c.startSweeper()
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "expire_soon", "v1", 50*time.Millisecond)).To(Succeed())
		Expect(c.Set(context.Background(), "keep", "v2", 0)).To(Succeed()) // no TTL

		// The sweeper should remove expire_soon within a short window.
		Eventually(func() bool { return c.Has(context.Background(), "expire_soon") }, "2s", "100ms").
			Should(BeFalse())

		// Non-expired entry must still be present.
		val, err := c.Get(context.Background(), "keep")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("v2"))
	})

	It("does not evict entries with zero expiresAt (no TTL)", func() {
		shard := newMemoryShard[string, string](100, 0)
		c := &MemoryCache[string, string]{
			shards:        []*memoryShard[string, string]{shard},
			mask:          0,
			seed:          maphash.MakeSeed(),
			stopCh:        make(chan struct{}),
			doneCh:        make(chan struct{}),
			sweepInterval: 10 * time.Millisecond,
		}
		c.startSweeper()
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "noexpire", "v", 0)).To(Succeed()) // no TTL

		// Give the sweeper enough ticks to prove it won't remove the entry.
		time.Sleep(200 * time.Millisecond)

		val, err := c.Get(context.Background(), "noexpire")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("v"))
	})

	It("stops the sweep goroutine on Close", func() {
		shard := newMemoryShard[string, string](100, time.Minute)
		c := &MemoryCache[string, string]{
			shards:        []*memoryShard[string, string]{shard},
			mask:          0,
			seed:          maphash.MakeSeed(),
			stopCh:        make(chan struct{}),
			doneCh:        make(chan struct{}),
			sweepInterval: time.Minute,
		}
		c.startSweeper()

		// Close must stop the goroutine and not block indefinitely.
		done := make(chan struct{})
		go func() {
			_ = c.Close()
			close(done)
		}()
		Eventually(done, "2s", "100ms").Should(BeClosed())

		// The goroutine must have closed doneCh.
		_, ok := <-c.doneCh
		Expect(ok).To(BeFalse())
	})

	It("is safe to call Close multiple times", func() {
		c := NewMemoryCache[string, string](100, time.Minute)
		_ = c.Close()
		// Second Close must not panic or block.
		_ = c.Close()
	})

	It("removes expired entries via direct sweep() call", func() {
		shard := newMemoryShard[string, string](100, time.Minute)
		c := &MemoryCache[string, string]{
			shards:        []*memoryShard[string, string]{shard},
			mask:          0,
			seed:          maphash.MakeSeed(),
			stopCh:        make(chan struct{}),
			doneCh:        make(chan struct{}),
			sweepInterval: time.Hour, // prevent automatic sweep
		}
		c.startSweeper()
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "will_expire", "v1", 50*time.Millisecond)).To(Succeed())
		Expect(c.Set(context.Background(), "will_keep", "v2", time.Hour)).To(Succeed())

		time.Sleep(100 * time.Millisecond)

		// Manual sweep.
		c.sweep()

		_, err := c.Get(context.Background(), "will_expire")
		Expect(err).To(MatchError(ErrNotFound))

		val, err := c.Get(context.Background(), "will_keep")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("v2"))
	})

	It("computeSweepInterval respects bounds", func() {
		Expect(computeSweepInterval(0)).To(Equal(30 * time.Second))
		Expect(computeSweepInterval(10 * time.Second)).To(Equal(30 * time.Second))
		Expect(computeSweepInterval(time.Minute)).To(Equal(30 * time.Second))
		Expect(computeSweepInterval(10 * time.Minute)).To(Equal(5 * time.Minute))
		Expect(computeSweepInterval(time.Hour)).To(Equal(5 * time.Minute))
	})
})

var _ = Describe("RingCache", func() {
	sharedCacheTests(func() Cache[string, string] {
		return NewRingCache[string, string](100, time.Minute)
	})

	It("should overwrite the oldest entry when full", func() {
		c := NewRingCache[string, string](3, time.Minute)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "a", "1", 0)).To(Succeed())
		Expect(c.Set(context.Background(), "b", "2", 0)).To(Succeed())
		Expect(c.Set(context.Background(), "c", "3", 0)).To(Succeed())
		Expect(c.Len(context.Background())).To(Equal(3))

		// Insert a 4th — "a" (oldest) should be overwritten
		Expect(c.Set(context.Background(), "d", "4", 0)).To(Succeed())
		Expect(c.Len(context.Background())).To(Equal(3))
		Expect(c.Has(context.Background(), "a")).To(BeFalse())
		Expect(c.Has(context.Background(), "b")).To(BeTrue())
		Expect(c.Has(context.Background(), "c")).To(BeTrue())
		Expect(c.Has(context.Background(), "d")).To(BeTrue())
	})

	It("should report Cap", func() {
		c := NewRingCache[string, string](16, 0)
		Expect(c.Cap()).To(Equal(16))
	})

	It("should update in place without consuming a new slot", func() {
		c := NewRingCache[string, string](3, time.Minute)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "a", "1", 0)).To(Succeed())
		Expect(c.Set(context.Background(), "b", "2", 0)).To(Succeed())
		Expect(c.Set(context.Background(), "c", "3", 0)).To(Succeed())

		// Update "a" — should not push out any entry
		Expect(c.Set(context.Background(), "a", "updated", 0)).To(Succeed())
		Expect(c.Len(context.Background())).To(Equal(3))
		val, err := c.Get(context.Background(), "a")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("updated"))
	})

	It("Range visits all live entries and skips expired ones", func() {
		c := NewRingCache[string, string](10, 0)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "a", "1", time.Minute)).To(Succeed())
		Expect(c.Set(context.Background(), "b", "2", time.Minute)).To(Succeed())
		Expect(c.Set(context.Background(), "exp", "x", time.Nanosecond)).To(Succeed())
		time.Sleep(5 * time.Millisecond) // let "exp" expire

		seen := map[string]string{}
		c.Range(context.Background(), func(k, v string) bool {
			seen[k] = v
			return true
		})
		Expect(seen).To(HaveKeyWithValue("a", "1"))
		Expect(seen).To(HaveKeyWithValue("b", "2"))
		Expect(seen).ToNot(HaveKey("exp"))
	})

	It("Range stops early when fn returns false", func() {
		c := NewRingCache[string, string](10, time.Minute)
		defer func() { _ = c.Close() }()

		for _, k := range []string{"a", "b", "c", "d"} {
			Expect(c.Set(context.Background(), k, k, 0)).To(Succeed())
		}
		count := 0
		c.Range(context.Background(), func(_, _ string) bool {
			count++
			return count < 2
		})
		Expect(count).To(Equal(2))
	})
})

var _ = Describe("ChainCache", func() {
	newChain := func() (*MemoryCache[string, string], *MemoryCache[string, string], *ChainCache[string, string]) {
		l1 := NewMemoryCache[string, string](100, time.Minute)
		l2 := NewMemoryCache[string, string](100, time.Minute)
		chain := NewChainCache[string, string](l1, l2, time.Minute)
		return l1, l2, chain
	}

	sharedCacheTests(func() Cache[string, string] {
		_, _, chain := newChain()
		return chain
	})

	It("should read from L1 first", func() {
		l1, _, chain := newChain()
		defer func() { _ = chain.Close() }()

		Expect(l1.Set(context.Background(), "k1", "from-l1", time.Minute)).To(Succeed())
		val, err := chain.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("from-l1"))
	})

	It("should fall back to L2 on L1 miss", func() {
		_, l2, chain := newChain()
		defer func() { _ = chain.Close() }()

		Expect(l2.Set(context.Background(), "k1", "from-l2", time.Minute)).To(Succeed())
		val, err := chain.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("from-l2"))
	})

	It("should promote L2 hit into L1", func() {
		l1, l2, chain := newChain()
		defer func() { _ = chain.Close() }()

		Expect(l2.Set(context.Background(), "k1", "from-l2", time.Minute)).To(Succeed())

		// Get triggers promotion
		_, err := chain.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())

		// Now L1 should have it
		val, err := l1.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("from-l2"))
	})

	It("should write-through to both levels", func() {
		l1, l2, chain := newChain()
		defer func() { _ = chain.Close() }()

		Expect(chain.Set(context.Background(), "k1", "both", time.Minute)).To(Succeed())

		v1, err := l1.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(v1).To(Equal("both"))

		v2, err := l2.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(v2).To(Equal("both"))
	})

	It("should delete from both levels", func() {
		l1, l2, chain := newChain()
		defer func() { _ = chain.Close() }()

		Expect(chain.Set(context.Background(), "k1", "both", time.Minute)).To(Succeed())
		Expect(chain.Del(context.Background(), "k1")).To(Succeed())

		Expect(l1.Has(context.Background(), "k1")).To(BeFalse())
		Expect(l2.Has(context.Background(), "k1")).To(BeFalse())
	})

	It("should return ErrNotFound when both levels miss", func() {
		_, _, chain := newChain()
		defer func() { _ = chain.Close() }()

		_, err := chain.Get(context.Background(), "missing")
		Expect(err).To(MatchError(ErrNotFound))
	})
})

var _ = Describe("ByteCache", func() {
	It("should set and get a value", func() {
		c := NewByteCache(1000, time.Minute)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", []byte("v1"), time.Minute)).To(Succeed())
		val, err := c.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal([]byte("v1")))
	})

	It("should return ErrNotFound for missing key", func() {
		c := NewByteCache(1000, time.Minute)
		defer func() { _ = c.Close() }()

		_, err := c.Get(context.Background(), "missing")
		Expect(err).To(MatchError(ErrNotFound))
	})

	It("should delete a key", func() {
		c := NewByteCache(1000, time.Minute)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", []byte("v1"), time.Minute)).To(Succeed())
		Expect(c.Del(context.Background(), "k1")).To(Succeed())
		_, err := c.Get(context.Background(), "k1")
		Expect(err).To(MatchError(ErrNotFound))
	})

	It("should report Has correctly", func() {
		c := NewByteCache(1000, time.Minute)
		defer func() { _ = c.Close() }()

		Expect(c.Has(context.Background(), "k1")).To(BeFalse())
		Expect(c.Set(context.Background(), "k1", []byte("v1"), time.Minute)).To(Succeed())
		Expect(c.Has(context.Background(), "k1")).To(BeTrue())
	})

	It("should flush all entries", func() {
		c := NewByteCache(1000, time.Minute)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "a", []byte("1"), time.Minute)).To(Succeed())
		Expect(c.Set(context.Background(), "b", []byte("2"), time.Minute)).To(Succeed())
		Expect(c.Flush(context.Background())).To(Succeed())
		Expect(c.Len(context.Background())).To(Equal(0))
		Expect(c.Used()).To(Equal(int64(0)))
	})

	It("should expire entries after TTL", func() {
		c := NewByteCache(1000, time.Minute)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", []byte("v1"), 50*time.Millisecond)).To(Succeed())
		time.Sleep(100 * time.Millisecond)
		_, err := c.Get(context.Background(), "k1")
		Expect(err).To(MatchError(ErrNotFound))
	})

	It("should evict LRU entries when byte budget is exceeded", func() {
		// Budget: 512 bytes. Each entry: len(key) + len(value).
		// Keys "0".."99" with 5-byte values ≈ 6-7 bytes each → ~650 bytes total > 512.
		c := NewByteCache(512, time.Minute)
		defer func() { _ = c.Close() }()

		for i := 0; i < 100; i++ {
			Expect(c.Set(context.Background(), strconv.Itoa(i), []byte("value"), 0)).To(Succeed())
		}

		// Some must have been evicted to stay within budget.
		Expect(c.Used()).To(BeNumerically("<=", int64(512)))
		Expect(c.Len(context.Background())).To(BeNumerically("<", 100))
	})

	It("should track Used and Capacity correctly", func() {
		c := NewByteCache(1600, time.Minute)
		defer func() { _ = c.Close() }()

		// 1600 / 16 shards = 100 per shard, total = 1600
		Expect(c.Capacity()).To(Equal(int64(1600)))
		Expect(c.Used()).To(Equal(int64(0)))

		// "key" (3) + "value" (5) = 8 bytes
		Expect(c.Set(context.Background(), "key", []byte("value"), time.Minute)).To(Succeed())
		Expect(c.Used()).To(Equal(int64(8)))

		Expect(c.Del(context.Background(), "key")).To(Succeed())
		Expect(c.Used()).To(Equal(int64(0)))
	})

	It("should update an existing key and adjust byte usage", func() {
		c := NewByteCache(1000, time.Minute)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", []byte("short"), 0)).To(Succeed())       // 2 + 5 = 7
		Expect(c.Set(context.Background(), "k1", []byte("much longer"), 0)).To(Succeed()) // 2 + 11 = 13
		Expect(c.Used()).To(Equal(int64(13)))
		Expect(c.Len(context.Background())).To(Equal(1))

		val, err := c.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal([]byte("much longer")))
	})

	It("should use default capacity when given 0", func() {
		c := NewByteCache(0, time.Minute)
		// 200 MiB default, distributed across shards: per-shard truncation is exact here.
		Expect(c.Capacity()).To(Equal(int64(200 * 1024 * 1024)))
	})

	It("should return ErrValueTooLarge when entry exceeds shard capacity", func() {
		// 1 shard (capacity < defaultByteShards) with 32-byte budget.
		c := NewByteCache(32, time.Minute)
		defer func() { _ = c.Close() }()

		oversized := make([]byte, 100)
		err := c.Set(context.Background(), "big", oversized, time.Minute)
		Expect(err).To(MatchError(ErrValueTooLarge))

		// Cache should remain empty — the entry must not have been inserted.
		Expect(c.Len(context.Background())).To(Equal(0))
		Expect(c.Used()).To(Equal(int64(0)))
	})

	It("should be safe for concurrent access", func() {
		c := NewByteCache(10000, time.Minute)
		defer func() { _ = c.Close() }()

		var wg sync.WaitGroup
		for range 100 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				key := "k"
				Expect(c.Set(context.Background(), key, []byte("v"), time.Minute)).To(Succeed())
				_, _ = c.Get(context.Background(), key)
				c.Has(context.Background(), key)
				c.Len(context.Background())
			}()
		}
		wg.Wait()
	})

	// Edge: an entry whose size exactly matches per-shard capacity must be
	// accepted, not rejected. `newSize > capacity` rejects only strictly larger.
	It("accepts an entry exactly at per-shard capacity", func() {
		// shards=1 → per-shard capacity == total capacity.
		c := NewByteCacheWithShards(10, 1, time.Minute)
		defer func() { _ = c.Close() }()

		// key "k" (1 byte) + value (9 bytes) = 10 bytes == capacity.
		err := c.Set(context.Background(), "k", make([]byte, 9), 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(c.Used()).To(Equal(int64(10)))
	})

	// Regression: a value that fits the total budget must not be
	// rejected because per-shard budget is too small. NewByteCache
	// auto-sizes shard count so per-shard budget stays >= 4 KiB — a
	// 1000-byte cache collapses to a single shard, fitting any value
	// up to ~1000 bytes.
	It("accepts a value that fits total budget", func() {
		c := NewByteCache(1000, time.Minute)
		defer func() { _ = c.Close() }()
		Expect(c.Shards()).To(Equal(1))

		err := c.Set(context.Background(), "k", make([]byte, 200), 0)
		Expect(err).ToNot(HaveOccurred())
	})

	// ErrValueTooLarge still fires when an entry exceeds the actual
	// per-shard budget. With a generous capacity that doesn't collapse,
	// each shard gets capacity/16 — a value exceeding that per-shard
	// budget must be rejected.
	It("rejects an entry larger than per-shard capacity", func() {
		// 1 MiB / 16 shards = 64 KiB per shard (above 4 KiB floor, no collapse).
		c := NewByteCache(1<<20, time.Minute)
		defer func() { _ = c.Close() }()

		// 128 KiB entry: larger than any single 64 KiB shard.
		err := c.Set(context.Background(), "k", make([]byte, 128*1024), 0)
		Expect(err).To(MatchError(ErrValueTooLarge))
	})

	// NewByteCache auto-picks shard count so per-shard budget stays at
	// or above the 4 KiB floor. This guarantees that any value fitting
	// the total capacity fits in its assigned shard — the property the
	// user actually wants from "a fixed-size byte cache."
	DescribeTable("NewByteCache auto-sizes shards to keep per-shard >= 4 KiB",
		func(capacity int64, wantShards int) {
			c := NewByteCache(capacity, time.Minute)
			defer func() { _ = c.Close() }()
			Expect(c.Shards()).To(Equal(wantShards),
				"capacity=%d wantShards=%d got=%d", capacity, wantShards, c.Shards())
			Expect(c.Capacity()).To(BeNumerically(">=", capacity))
		},
		// Tiny capacities: single shard.
		Entry("capacity=1 -> 1 shard", int64(1), 1),
		Entry("capacity=4095 -> 1 shard", int64(4095), 1),
		Entry("capacity=4096 -> 1 shard", int64(4096), 1),
		// 8 KiB total fits 2 shards of 4 KiB each.
		Entry("capacity=8192 -> 2 shards", int64(8192), 2),
		Entry("capacity=16384 -> 4 shards", int64(16384), 4),
		Entry("capacity=32768 -> 8 shards", int64(32768), 8),
		Entry("capacity=65536 -> 16 shards (floor at DefaultByteShards)", int64(65536), 16),
		// Past the floor threshold, auto-sizing caps at DefaultByteShards.
		Entry("capacity=1MiB -> 16 shards (capped at default)", int64(1<<20), 16),
		Entry("capacity=200MiB -> 16 shards", int64(200*1024*1024), 16),
	)

	// A small cache holding a single near-capacity entry: per-shard
	// sharding caps individual entries at capacity/shards. Callers who
	// need a single entry to consume most of the budget must pass
	// shards=1 explicitly — NewByteCache's auto-sizing preserves some
	// concurrency and will not collapse all the way to 1 by default.
	It("honors explicit shards=1 for a single large value", func() {
		c := NewByteCacheWithShards(20*1024, 1, time.Minute)
		defer func() { _ = c.Close() }()
		Expect(c.Shards()).To(Equal(1))
		Expect(c.Set(context.Background(), "big", make([]byte, 19*1024), 0)).To(Succeed())
	})

	// NewByteCacheWithShards honors the caller's shard count exactly,
	// even when per-shard budget falls below the 4 KiB floor. This is
	// deliberate: callers using the explicit constructor are signaling
	// a topology (e.g. one shard per node in a future distributed
	// cache) and must not have their shard count silently rewritten.
	DescribeTable("NewByteCacheWithShards honors shards exactly",
		func(capacity int64, shards, wantShards int) {
			c := NewByteCacheWithShards(capacity, shards, time.Minute)
			defer func() { _ = c.Close() }()
			Expect(c.Shards()).To(Equal(wantShards),
				"capacity=%d shards=%d wantShards=%d got=%d",
				capacity, shards, wantShards, c.Shards())
		},
		// shards is rounded up to the next power of two, but never collapsed.
		Entry("capacity=1KiB shards=16 -> 16 (below floor but honored)", int64(1024), 16, 16),
		Entry("capacity=8KiB shards=16 -> 16", int64(8*1024), 16, 16),
		Entry("capacity=1MiB shards=16 -> 16", int64(1<<20), 16, 16),
		Entry("capacity=1MiB shards=1 -> 1 (explicit single shard)", int64(1<<20), 1, 1),
		Entry("capacity=1MiB shards=3 -> 4 (nextPow2)", int64(1<<20), 3, 4),
		Entry("capacity=1MiB shards=7 -> 8 (nextPow2)", int64(1<<20), 7, 8),
	)

	It("falls back to default capacity when capacity <= 0", func() {
		c := NewByteCache(0, time.Minute)
		defer func() { _ = c.Close() }()
		// 200 MiB default; confirm Capacity() reports it and the cache
		// accepts inserts rather than rejecting everything.
		Expect(c.Capacity()).To(Equal(int64(200 * 1024 * 1024)))
		Expect(c.Set(context.Background(), "k", []byte("v"), 0)).To(Succeed())
	})

	It("falls back to default shards when shards <= 0", func() {
		// shards=0 → DefaultByteShards=16. Capacity 1600 → 100 per shard.
		c := NewByteCacheWithShards(1600, 0, time.Minute)
		defer func() { _ = c.Close() }()
		Expect(c.Capacity()).To(Equal(int64(1600)))

		// Same for negative.
		c2 := NewByteCacheWithShards(1600, -3, time.Minute)
		defer func() { _ = c2.Close() }()
		Expect(c2.Capacity()).To(Equal(int64(1600)))
	})

	// Edge: nextPow2 rounds odd shard counts up before collapse runs.
	DescribeTable("rounds non-pow2 shards via nextPow2",
		func(shards, wantShards int) {
			// Large capacity so collapse doesn't kick in.
			c := NewByteCacheWithShards(1<<20, shards, time.Minute)
			defer func() { _ = c.Close() }()
			perShard := (int64(1<<20) + int64(wantShards) - 1) / int64(wantShards)
			Expect(c.Capacity()).To(Equal(perShard * int64(wantShards)))
		},
		Entry("shards=3 rounds to 4", 3, 4),
		Entry("shards=5 rounds to 8", 5, 8),
		Entry("shards=7 rounds to 8", 7, 8),
		Entry("shards=9 rounds to 16", 9, 16),
		Entry("shards=16 stays 16", 16, 16),
	)

	// Edge: empty value is a valid entry (key-only); entry size equals
	// len(key). Confirms no "value must be non-empty" assumption leaks in.
	It("accepts an empty value", func() {
		c := NewByteCache(1000, time.Minute)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", []byte{}, 0)).To(Succeed())
		Expect(c.Has(context.Background(), "k1")).To(BeTrue())
		Expect(c.Used()).To(Equal(int64(2))) // "k1" is 2 bytes

		val, err := c.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(HaveLen(0))
	})

	// Edge: updating a key with a smaller value must release the freed
	// bytes so subsequent inserts aren't pushed over budget.
	It("releases bytes when updating to a smaller value", func() {
		c := NewByteCacheWithShards(20, 1, time.Minute)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", make([]byte, 15), 0)).To(Succeed()) // 2 + 15 = 17 used, fits in 20
		Expect(c.Used()).To(Equal(int64(17)))

		// Shrink: 2 + 3 = 5; Used must drop to 5, not stay at 17.
		Expect(c.Set(context.Background(), "k1", []byte("abc"), 0)).To(Succeed())
		Expect(c.Used()).To(Equal(int64(5)))

		// There's now room for another 15-byte entry (17 - 5 = 12 freed).
		Expect(c.Set(context.Background(), "k2", make([]byte, 10), 0)).To(Succeed())
		Expect(c.Used()).To(Equal(int64(17))) // 5 + 12
	})

	// Edge: insert a value that forces eviction of multiple older entries
	// before it fits. evictUntilFit must remove entries in LRU order
	// rather than stopping early.
	It("evicts multiple entries to fit a larger incoming value", func() {
		c := NewByteCacheWithShards(20, 1, time.Minute)
		defer func() { _ = c.Close() }()

		// Four 4-byte entries (1-byte key + 3-byte value): 16 used.
		Expect(c.Set(context.Background(), "a", []byte("aaa"), 0)).To(Succeed())
		Expect(c.Set(context.Background(), "b", []byte("bbb"), 0)).To(Succeed())
		Expect(c.Set(context.Background(), "c", []byte("ccc"), 0)).To(Succeed())
		Expect(c.Set(context.Background(), "d", []byte("ddd"), 0)).To(Succeed())
		Expect(c.Used()).To(Equal(int64(16)))
		Expect(c.Len(context.Background())).To(Equal(4))

		// 17-byte incoming (1 + 16) forces eviction of several entries.
		// LRU order is a, b, c, d (a is oldest). Capacity=20, so
		// everything before the new entry must go.
		Expect(c.Set(context.Background(), "x", make([]byte, 16), 0)).To(Succeed())
		Expect(c.Used()).To(BeNumerically("<=", int64(20)))

		// "a" (oldest) must be gone.
		_, err := c.Get(context.Background(), "a")
		Expect(err).To(MatchError(ErrNotFound))
		// "x" must be present.
		_, err = c.Get(context.Background(), "x")
		Expect(err).ToNot(HaveOccurred())
	})

	// WithLogger threads the app's structured logger into the cache so
	// shard-budget warnings land in the same JSON log stream as the rest
	// of the service. Operators must not have to grep stderr text.
	It("emits per-shard-floor warnings through the supplied zap logger", func() {
		core, logs := observer.New(zapcore.WarnLevel)
		// 16 shards × 1 KiB total -> per-shard 64 bytes, well below 4 KiB.
		c := NewByteCacheWithShards(1024, 16, time.Minute, WithLogger(log.New(zap.New(core))))
		defer func() { _ = c.Close() }()
		Expect(logs.FilterMessageSnippet("per-shard budget is below floor").Len()).
			To(Equal(1))
	})

	// Above-floor construction must emit zero warnings even when a logger
	// is supplied — confirms the warning is gated on the shard-budget
	// condition, not unconditionally spammed.
	It("emits no warnings when per-shard budget stays above the floor", func() {
		core, logs := observer.New(zapcore.DebugLevel)
		// 16 shards × 1 MiB -> 64 KiB per shard, comfortably above 4 KiB.
		c := NewByteCacheWithShards(1<<20, 16, time.Minute, WithLogger(log.New(zap.New(core))))
		defer func() { _ = c.Close() }()
		Expect(logs.Len()).To(Equal(0))
	})

	It("is silent when WithLogger is omitted (defaults to no-op)", func() {
		// Default must be zap.NewNop(), not a stdlib fallback. We can't
		// intercept a no-op logger directly, but we can assert that
		// construction completes and the cache is usable; combined with
		// the build-level grep for `log.Printf` in production code
		// (done in H1 review), this pins the contract.
		c := NewByteCacheWithShards(1024, 16, time.Minute)
		defer func() { _ = c.Close() }()
		Expect(c.Shards()).To(Equal(16))
	})
})

var _ = Describe("ByteCache sweeper", func() {
	It("removes expired entries via background sweep", func() {
		shard := newByteShard(1000, time.Minute)
		c := &ByteCache{
			shards:        []*byteShard{shard},
			mask:          0,
			seed:          maphash.MakeSeed(),
			stopCh:        make(chan struct{}),
			doneCh:        make(chan struct{}),
			sweepInterval: 10 * time.Millisecond,
		}
		c.startSweeper()
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "expire_soon", []byte("v1"), 50*time.Millisecond)).To(Succeed())
		Expect(c.Set(context.Background(), "keep", []byte("v2"), 0)).To(Succeed()) // no TTL

		// The sweeper should remove expire_soon within a short window.
		Eventually(func() bool { return c.Has(context.Background(), "expire_soon") }, "2s", "100ms").
			Should(BeFalse())

		// Non-expired entry must still be present.
		val, err := c.Get(context.Background(), "keep")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal([]byte("v2")))
	})

	It("does not evict entries with zero expiresAt (no TTL)", func() {
		shard := newByteShard(1000, 0)
		c := &ByteCache{
			shards:        []*byteShard{shard},
			mask:          0,
			seed:          maphash.MakeSeed(),
			stopCh:        make(chan struct{}),
			doneCh:        make(chan struct{}),
			sweepInterval: 10 * time.Millisecond,
		}
		c.startSweeper()
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "noexpire", []byte("v"), 0)).To(Succeed()) // no TTL

		// Give the sweeper enough ticks to prove it won't remove the entry.
		time.Sleep(200 * time.Millisecond)

		val, err := c.Get(context.Background(), "noexpire")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal([]byte("v")))
	})

	It("stops the sweep goroutine on Close", func() {
		shard := newByteShard(1000, time.Minute)
		c := &ByteCache{
			shards:        []*byteShard{shard},
			mask:          0,
			seed:          maphash.MakeSeed(),
			stopCh:        make(chan struct{}),
			doneCh:        make(chan struct{}),
			sweepInterval: time.Minute,
		}
		c.startSweeper()

		// Close must stop the goroutine and not block indefinitely.
		done := make(chan struct{})
		go func() {
			_ = c.Close()
			close(done)
		}()
		Eventually(done, "2s", "100ms").Should(BeClosed())

		// The goroutine must have closed doneCh.
		_, ok := <-c.doneCh
		Expect(ok).To(BeFalse())
	})

	It("is safe to call Close multiple times", func() {
		c := NewByteCache(1000, time.Minute)
		_ = c.Close()
		// Second Close must not panic or block.
		_ = c.Close()
	})

	It("removes expired entries via direct sweep() call", func() {
		shard := newByteShard(1000, time.Minute)
		c := &ByteCache{
			shards:        []*byteShard{shard},
			mask:          0,
			seed:          maphash.MakeSeed(),
			stopCh:        make(chan struct{}),
			doneCh:        make(chan struct{}),
			sweepInterval: time.Hour, // prevent automatic sweep
		}
		c.startSweeper()
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "will_expire", []byte("v1"), 50*time.Millisecond)).To(Succeed())
		Expect(c.Set(context.Background(), "will_keep", []byte("v2"), time.Hour)).To(Succeed())

		time.Sleep(100 * time.Millisecond)

		// Manual sweep.
		c.sweep()

		_, err := c.Get(context.Background(), "will_expire")
		Expect(err).To(MatchError(ErrNotFound))

		val, err := c.Get(context.Background(), "will_keep")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal([]byte("v2")))
	})
})

var _ = Describe("Cache logger wiring", func() {
	It("MemoryCache emits shard-collapse warnings through the supplied logger", func() {
		core, logs := observer.New(zapcore.WarnLevel)
		// size=10, shards=16 -> collapse (10/16 < 16 per-shard floor).
		c := NewMemoryCacheWithShards[string, string](10, 16, time.Minute, WithLogger(log.New(zap.New(core))))
		defer func() { _ = c.Close() }()
		Expect(logs.FilterMessageSnippet("collapsed shards").Len()).To(Equal(1))
	})

	It("accepts a nil Option without panicking", func() {
		c := NewMemoryCacheWithShards[string, string](128, 4, time.Minute, nil)
		defer func() { _ = c.Close() }()
		Expect(c.Shards()).To(Equal(4))
	})
})

var _ = Describe("RedisCache", func() {
	var mr *miniredis.Miniredis

	BeforeEach(func() {
		var err error
		mr, err = miniredis.Run()
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		mr.Close()
	})

	newRedisCache := func() Cache[string, string] {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		return NewRedisCache[string, string](client, time.Minute)
	}

	sharedCacheTests(func() Cache[string, string] {
		return newRedisCache()
	}, false)

	It("should apply key prefix", func() {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		c := NewRedisCache[string, string](client, time.Minute, WithPrefix[string, string]("pfx::"))
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", "v1", time.Minute)).To(Succeed())
		// The key in Redis should be prefixed
		Expect(mr.Exists("pfx::k1")).To(BeTrue())
		Expect(mr.Exists("k1")).To(BeFalse())

		val, err := c.Get(context.Background(), "k1")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("v1"))
	})

	It("should respect per-key TTL via Redis PTTL", func() {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		c := NewRedisCache[string, string](client, time.Hour)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "short", "v", 200*time.Millisecond)).To(Succeed())

		// Fast-forward miniredis time
		mr.FastForward(300 * time.Millisecond)

		_, err := c.Get(context.Background(), "short")
		Expect(err).To(MatchError(ErrNotFound))
	})

	It("should use default TTL when per-key TTL is 0", func() {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		c := NewRedisCache[string, string](client, 200*time.Millisecond)
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "k1", "v1", 0)).To(Succeed())
		mr.FastForward(300 * time.Millisecond)

		_, err := c.Get(context.Background(), "k1")
		Expect(err).To(MatchError(ErrNotFound))
	})

	It("should handle Flush correctly", func() {
		c := newRedisCache()
		defer func() { _ = c.Close() }()

		Expect(c.Set(context.Background(), "a", "1", time.Minute)).To(Succeed())
		Expect(c.Set(context.Background(), "b", "2", time.Minute)).To(Succeed())
		Expect(c.Flush(context.Background())).To(Succeed())

		_, err := c.Get(context.Background(), "a")
		Expect(err).To(MatchError(ErrNotFound))
		_, err = c.Get(context.Background(), "b")
		Expect(err).To(MatchError(ErrNotFound))
	})

	It("should close the redis client", func() {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		c := NewRedisCache[string, string](client, time.Minute)

		Expect(c.Close()).To(Succeed())
	})

	It("is safe to call Close multiple times", func() {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		c := NewRedisCache[string, string](client, time.Minute)

		Expect(c.Close()).To(Succeed())
		Expect(c.Close()).To(Succeed())
		Expect(c.Close()).To(Succeed())
	})

	It("should treat windowTTL=0 as never expire in Increment", func() {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		c := NewRedisCache[string, []byte](client, time.Minute)
		defer func() { _ = c.Close() }()

		ctx := context.Background()
		count, err := c.Increment(ctx, "noexp", 1, 100, 0, time.Minute)
		Expect(err).ToNot(HaveOccurred())
		Expect(count).To(BeEquivalentTo(1))

		// Fast-forward well past the blockTTL — the key must still exist because
		// windowTTL=0 means no expiry on first write.
		mr.FastForward(time.Hour)

		raw, err := c.Get(ctx, "noexp")
		Expect(err).ToNot(HaveOccurred())
		Expect(len(raw)).To(Equal(8))
	})

	It("should count only prefixed keys in Len()", func() {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		c1 := NewRedisCache[string, string](client, time.Minute, WithPrefix[string, string]("a::"))
		c2 := NewRedisCache[string, string](client, time.Minute, WithPrefix[string, string]("b::"))

		Expect(c1.Set(context.Background(), "x", "1", time.Minute)).To(Succeed())
		Expect(c1.Set(context.Background(), "y", "2", time.Minute)).To(Succeed())
		Expect(c2.Set(context.Background(), "x", "3", time.Minute)).To(Succeed())

		Expect(c1.Len(context.Background())).To(Equal(2))
		Expect(c2.Len(context.Background())).To(Equal(1))
	})

	It("should flush only prefixed keys when prefix is set", func() {
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		c1 := NewRedisCache[string, string](client, time.Minute, WithPrefix[string, string]("a::"))
		c2 := NewRedisCache[string, string](client, time.Minute, WithPrefix[string, string]("b::"))

		Expect(c1.Set(context.Background(), "x", "1", time.Minute)).To(Succeed())
		Expect(c1.Set(context.Background(), "y", "2", time.Minute)).To(Succeed())
		Expect(c2.Set(context.Background(), "x", "3", time.Minute)).To(Succeed())

		Expect(c1.Flush(context.Background())).To(Succeed())

		// c1's keys should be gone
		Expect(c1.Len(context.Background())).To(Equal(0))
		_, err := c1.Get(context.Background(), "x")
		Expect(err).To(MatchError(ErrNotFound))

		// c2's keys should be untouched
		Expect(c2.Len(context.Background())).To(Equal(1))
		val, err := c2.Get(context.Background(), "x")
		Expect(err).ToNot(HaveOccurred())
		Expect(val).To(Equal("3"))
	})
})

// sharedIncrementTests runs the shared Increment conformance tests against any
// cache that implements the atomicIncrementer contract.
// newCache must return a fresh *ByteCache or similar whose Increment is under test.
type atomicIncrementerTestable interface {
	Increment(ctx context.Context, key string, delta, limit uint64, windowTTL, blockTTL time.Duration) (uint64, error)
	Get(ctx context.Context, key string) ([]byte, error)
	Close() error
}

func sharedIncrementTests(newCache func() atomicIncrementerTestable) {
	It("should atomically increment counter", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		ctx := context.Background()
		count, err := c.Increment(ctx, "ctr", 1, 10, time.Minute, 15*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		Expect(count).To(BeEquivalentTo(1))

		count, err = c.Increment(ctx, "ctr", 1, 10, time.Minute, 15*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		Expect(count).To(BeEquivalentTo(2))
	})

	It("should not increment once limit is reached", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		ctx := context.Background()
		const limit = 3
		for range limit {
			_, err := c.Increment(ctx, "blocked", 1, limit, time.Minute, 15*time.Minute)
			Expect(err).ToNot(HaveOccurred())
		}
		// At limit — further calls must be no-ops.
		count, err := c.Increment(ctx, "blocked", 1, limit, time.Minute, 15*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		Expect(count).To(BeEquivalentTo(limit))

		raw, err := c.Get(ctx, "blocked")
		Expect(err).ToNot(HaveOccurred())
		Expect(len(raw)).To(Equal(8))
		Expect(binary.BigEndian.Uint64(raw)).To(BeEquivalentTo(limit))
	})

	It("should not reset TTL once limit is reached", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		ctx := context.Background()
		const limit = 2
		for range limit {
			_, err := c.Increment(ctx, "key", 1, limit, time.Minute, 15*time.Minute)
			Expect(err).ToNot(HaveOccurred())
		}
		// Counter is at limit; calling again must leave count unchanged.
		count, err := c.Increment(ctx, "key", 1, limit, time.Minute, 15*time.Minute)
		Expect(err).ToNot(HaveOccurred())
		Expect(count).To(BeEquivalentTo(limit))
	})

	It("should fallback blockTTL to defaultTTL when zero", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		ctx := context.Background()
		// blockTTL=0 must not panic; the implementation falls back to the shard's defaultTTL.
		count, err := c.Increment(ctx, "fb", 1, 1, time.Minute, 0)
		Expect(err).ToNot(HaveOccurred())
		Expect(count).To(BeEquivalentTo(1))

		// The entry must exist.
		raw, err := c.Get(ctx, "fb")
		Expect(err).ToNot(HaveOccurred())
		Expect(len(raw)).To(Equal(8))
	})

	It("should be race-free under concurrent increments", func() {
		c := newCache()
		defer func() { _ = c.Close() }()

		const goroutines = 50
		const limit = goroutines + 1 // keep limit above goroutine count so no call is a no-op

		ctx := context.Background()
		key := "race-key"

		var wg sync.WaitGroup
		wg.Add(goroutines)
		for range goroutines {
			go func() {
				defer wg.Done()
				_, _ = c.Increment(ctx, key, 1, limit, time.Minute, 15*time.Minute)
			}()
		}
		wg.Wait()

		raw, err := c.Get(ctx, key)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(raw)).To(Equal(8))
		Expect(binary.BigEndian.Uint64(raw)).To(BeEquivalentTo(goroutines))
	})
}

var _ = Describe("ByteCache.Increment", func() {
	sharedIncrementTests(func() atomicIncrementerTestable {
		// 10 MiB, 1-minute default TTL — mirrors NewFromConfig production sizing.
		return NewByteCache(10*1024*1024, time.Minute)
	})
})

var _ = Describe("ChainCache.Increment (ByteCache L1 + miniredis L2)", func() {
	var mr *miniredis.Miniredis

	BeforeEach(func() {
		var err error
		mr, err = miniredis.Run()
		Expect(err).ToNot(HaveOccurred())
	})

	AfterEach(func() {
		mr.Close()
	})

	newChainForIncrement := func() atomicIncrementerTestable {
		l1 := NewByteCache(10*1024*1024, time.Minute)
		client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
		l2 := NewRedisCache[string, []byte](client, time.Minute)
		return NewChainCache(l1, l2, time.Minute)
	}

	sharedIncrementTests(newChainForIncrement)

	It("should return error when L2 does not implement Increment", func() {
		// Use a MemoryCache as L2 — it does implement Increment, so wrap it
		// in a type that strips the method.
		type noIncrementCache struct{ Cache[string, []byte] }
		l1 := NewByteCache(1*1024*1024, time.Minute)
		l2 := NewMemoryCache[string, []byte](100, time.Minute)
		chain := NewChainCache(l1, &noIncrementCache{l2}, time.Minute)
		defer func() { _ = chain.Close() }()

		_, err := chain.Increment(context.Background(), "k", 1, 10, time.Minute, 15*time.Minute)
		Expect(err).To(HaveOccurred())
		Expect(err.Error()).To(ContainSubstring("does not implement Increment"))
	})

	Describe("NewFromConfig", func() {
		It("returns ByteCache when Redis addr is empty", func() {
			cfg := ezcfg.StoreCacheConfig{
				Memory: ezcfg.MemoryCacheConfig{Size: "1k", TTL: time.Minute},
			}
			c, err := NewFromConfig(cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(c).NotTo(BeNil())
			_ = c.Close()
		})

		It("returns error for invalid memory size", func() {
			cfg := ezcfg.StoreCacheConfig{
				Memory: ezcfg.MemoryCacheConfig{Size: "invalid-size", TTL: time.Minute},
			}
			_, err := NewFromConfig(cfg)
			Expect(err).To(HaveOccurred())
		})

		It("returns ByteCache when size is empty (defaults)", func() {
			cfg := ezcfg.StoreCacheConfig{
				Memory: ezcfg.MemoryCacheConfig{Size: "", TTL: time.Minute},
			}
			c, err := NewFromConfig(cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(c).NotTo(BeNil())
			_ = c.Close()
		})

		It("returns ChainCache when Redis addr is configured", func() {
			mr, mrErr := miniredis.Run()
			Expect(mrErr).ToNot(HaveOccurred())
			defer mr.Close()

			cfg := ezcfg.StoreCacheConfig{
				Memory: ezcfg.MemoryCacheConfig{Size: "1k", TTL: time.Minute},
				Redis:  ezcfg.RedisConfig{Addr: mr.Addr(), TTL: time.Minute},
			}
			c, err := NewFromConfig(cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(c).NotTo(BeNil())
			_ = c.Close()
		})

		It("uses default promoteTTL when Memory TTL is 0", func() {
			mr, mrErr := miniredis.Run()
			Expect(mrErr).ToNot(HaveOccurred())
			defer mr.Close()

			cfg := ezcfg.StoreCacheConfig{
				Memory: ezcfg.MemoryCacheConfig{Size: "1k", TTL: 0},
				Redis:  ezcfg.RedisConfig{Addr: mr.Addr(), TTL: time.Minute},
			}
			c, err := NewFromConfig(cfg)
			Expect(err).ToNot(HaveOccurred())
			Expect(c).NotTo(BeNil())
			_ = c.Close()
		})
	})

	Describe("MemoryCache Increment and Range", func() {
		It("Increment atomically counts", func() {
			c := NewMemoryCache[string, []byte](100, time.Minute)
			defer func() { _ = c.Close() }()

			ctx := context.Background()
			count, err := c.Increment(ctx, "ctr", 1, 10, time.Minute, 15*time.Minute)
			Expect(err).ToNot(HaveOccurred())
			Expect(count).To(BeEquivalentTo(1))

			count, err = c.Increment(ctx, "ctr", 1, 10, time.Minute, 15*time.Minute)
			Expect(err).ToNot(HaveOccurred())
			Expect(count).To(BeEquivalentTo(2))
		})

		It("Range visits all live entries", func() {
			c := NewMemoryCache[string, string](100, time.Minute)
			defer func() { _ = c.Close() }()

			ctx := context.Background()
			Expect(c.Set(ctx, "a", "1", time.Minute)).To(Succeed())
			Expect(c.Set(ctx, "b", "2", time.Minute)).To(Succeed())

			seen := map[string]string{}
			c.Range(ctx, func(k, v string) bool {
				seen[k] = v
				return true
			})
			Expect(seen).To(HaveKeyWithValue("a", "1"))
			Expect(seen).To(HaveKeyWithValue("b", "2"))
		})

		It("Range stops early when fn returns false", func() {
			c := NewMemoryCache[string, string](100, time.Minute)
			defer func() { _ = c.Close() }()

			ctx := context.Background()
			for _, k := range []string{"a", "b", "c"} {
				Expect(c.Set(ctx, k, k, 0)).To(Succeed())
			}
			count := 0
			c.Range(ctx, func(_, _ string) bool {
				count++
				return count < 2
			})
			Expect(count).To(Equal(2))
		})
	})

	Describe("RingCache edge cases", func() {
		It("returns ErrNotFound for expired entry in Get", func() {
			c := NewRingCache[string, string](10, 0)
			defer func() { _ = c.Close() }()

			ctx := context.Background()
			Expect(c.Set(ctx, "exp", "x", time.Nanosecond)).To(Succeed())
			time.Sleep(5 * time.Millisecond)
			_, err := c.Get(ctx, "exp")
			Expect(err).To(MatchError(ErrNotFound))
		})

		It("falls back to default capacity when size <= 0", func() {
			c := NewRingCache[string, string](0, time.Minute)
			defer func() { _ = c.Close() }()
			Expect(c.Cap()).To(Equal(256))
		})
	})

})
