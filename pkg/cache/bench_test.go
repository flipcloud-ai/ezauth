//go:build benchmark

package cache

import (
	"context"
	"fmt"
	"math/rand/v2"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// ---------- helpers ----------

// preloadMemory fills a MemoryCache with n entries keyed "0"…"n-1".
func preloadMemory(n int) *MemoryCache[string, string] {
	c := NewMemoryCache[string, string](n, 0)
	for i := range n {
		_ = c.Set(context.Background(), strconv.Itoa(i), "value", 0)
	}
	return c
}

// preloadByteCache fills a ByteCache with n entries.
func preloadByteCache(n int) *ByteCache {
	// 64 bytes per entry is generous enough to avoid eviction during reads.
	c := NewByteCache(int64(n)*64, 0)
	val := []byte("value")
	for i := range n {
		_ = c.Set(context.Background(), strconv.Itoa(i), val, 0)
	}
	return c
}

// preloadRing fills a RingCache with 10000 entries.
func preloadRing() *RingCache[string, string] {
	const n = 10_000
	c := NewRingCache[string, string](n, 0)
	for i := range n {
		_ = c.Set(context.Background(), strconv.Itoa(i), "value", 0)
	}
	return c
}

// ---------- MemoryCache ----------

func BenchmarkMemoryCache_Set(b *testing.B) {
	c := NewMemoryCache[string, string](b.N, 0)
	b.ResetTimer()
	for i := range b.N {
		_ = c.Set(context.Background(), strconv.Itoa(i), "value", 0)
	}
}

func BenchmarkMemoryCache_Get_Hit(b *testing.B) {
	const size = 10_000
	c := preloadMemory(size)

	b.ResetTimer()
	for i := range b.N {
		_, _ = c.Get(context.Background(), strconv.Itoa(i%size))
	}
}

func BenchmarkMemoryCache_Get_Miss(b *testing.B) {
	c := preloadMemory(1000)

	b.ResetTimer()
	for i := range b.N {
		_, _ = c.Get(context.Background(), "miss-"+strconv.Itoa(i))
	}
}

func BenchmarkMemoryCache_Mixed(b *testing.B) {
	const size = 10_000
	c := preloadMemory(size)

	b.ResetTimer()
	for i := range b.N {
		key := strconv.Itoa(i % size)
		if i%10 < 8 { // 80% reads
			_, _ = c.Get(context.Background(), key)
		} else {
			_ = c.Set(context.Background(), key, "new", 0)
		}
	}
}

func BenchmarkMemoryCache_Parallel(b *testing.B) {
	const size = 10_000
	c := preloadMemory(size)

	b.ResetTimer()
	var ops atomic.Int64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(ops.Add(1))
			key := strconv.Itoa(i % size)
			if i%10 < 8 {
				_, _ = c.Get(context.Background(), key)
			} else {
				_ = c.Set(context.Background(), key, "v", 0)
			}
		}
	})
}

// ---------- Shard-count sweep ----------
//
// These benchmarks hold total size fixed and vary the shard count to measure
// how sharding affects throughput under contention. Run with:
//
//	go test -bench=BenchmarkMemoryCache_Shards -benchmem ./pkg/cache
//
// Low shard counts should show higher contention (slower) on parallel
// workloads; the benefit should flatten past the CPU count.

var shardCounts = []int{1, 2, 4, 8, 16, 32, 64, 128}

// preloadMemoryWithShards fills a MemoryCache of the given size/shards.
func preloadMemoryWithShards(size, shards int) *MemoryCache[string, string] {
	c := NewMemoryCacheWithShards[string, string](size, shards, 0)
	for i := range size {
		_ = c.Set(context.Background(), strconv.Itoa(i), "value", 0)
	}
	return c
}

func BenchmarkMemoryCache_Shards_Parallel_Read(b *testing.B) {
	const size = 10_000
	for _, shards := range shardCounts {
		b.Run(fmt.Sprintf("shards=%d", shards), func(b *testing.B) {
			c := preloadMemoryWithShards(size, shards)
			var ops atomic.Int64
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					i := int(ops.Add(1))
					_, _ = c.Get(context.Background(), strconv.Itoa(i%size))
				}
			})
		})
	}
}

func BenchmarkMemoryCache_Shards_Parallel_Write(b *testing.B) {
	const size = 10_000
	for _, shards := range shardCounts {
		b.Run(fmt.Sprintf("shards=%d", shards), func(b *testing.B) {
			c := preloadMemoryWithShards(size, shards)
			var ops atomic.Int64
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					i := int(ops.Add(1))
					_ = c.Set(context.Background(), strconv.Itoa(i%size), "v", 0)
				}
			})
		})
	}
}

func BenchmarkMemoryCache_Shards_Parallel_Mixed(b *testing.B) {
	const size = 10_000
	for _, shards := range shardCounts {
		b.Run(fmt.Sprintf("shards=%d", shards), func(b *testing.B) {
			c := preloadMemoryWithShards(size, shards)
			var ops atomic.Int64
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					i := int(ops.Add(1))
					key := strconv.Itoa(i % size)
					if i%10 < 8 {
						_, _ = c.Get(context.Background(), key)
					} else {
						_ = c.Set(context.Background(), key, "v", 0)
					}
				}
			})
		})
	}
}

func BenchmarkMemoryCache_Shards_Serial_Set(b *testing.B) {
	const size = 10_000
	for _, shards := range shardCounts {
		b.Run(fmt.Sprintf("shards=%d", shards), func(b *testing.B) {
			c := NewMemoryCacheWithShards[string, string](size, shards, 0)
			b.ResetTimer()
			for i := range b.N {
				_ = c.Set(context.Background(), strconv.Itoa(i%size), "v", 0)
			}
		})
	}
}

// ---------- ByteCache ----------

func BenchmarkByteCache_Set(b *testing.B) {
	c := NewByteCache(int64(b.N)*64, 0)
	val := []byte("value")
	b.ResetTimer()
	for i := range b.N {
		_ = c.Set(context.Background(), strconv.Itoa(i), val, 0)
	}
}

func BenchmarkByteCache_Get_Hit(b *testing.B) {
	const size = 10_000
	c := preloadByteCache(size)

	b.ResetTimer()
	for i := range b.N {
		_, _ = c.Get(context.Background(), strconv.Itoa(i%size))
	}
}

func BenchmarkByteCache_Get_Miss(b *testing.B) {
	c := preloadByteCache(1000)

	b.ResetTimer()
	for i := range b.N {
		_, _ = c.Get(context.Background(), "miss-"+strconv.Itoa(i))
	}
}

func BenchmarkByteCache_Eviction(b *testing.B) {
	// Small budget forces constant eviction.
	// Each entry ≈ 6 bytes (key "12345" + value "v"), so 600 bytes holds ~100 entries.
	c := NewByteCache(600, 0)
	val := []byte("v")
	b.ResetTimer()
	for i := range b.N {
		_ = c.Set(context.Background(), strconv.Itoa(i), val, 0)
	}
}

func BenchmarkByteCache_Parallel(b *testing.B) {
	const size = 10_000
	c := preloadByteCache(size)

	b.ResetTimer()
	var ops atomic.Int64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(ops.Add(1))
			key := strconv.Itoa(i % size)
			if i%10 < 8 {
				_, _ = c.Get(context.Background(), key)
			} else {
				_ = c.Set(context.Background(), key, []byte("v"), 0)
			}
		}
	})
}

// ---------- ByteCache shard-count sweep ----------

// preloadByteCacheWithShards fills a ByteCache with a fixed per-entry budget
// across the given shard count.
func preloadByteCacheWithShards(n, shards int) *ByteCache {
	c := NewByteCacheWithShards(int64(n)*64, shards, 0)
	val := []byte("value")
	for i := range n {
		_ = c.Set(context.Background(), strconv.Itoa(i), val, 0)
	}
	return c
}

func BenchmarkByteCache_Shards_Parallel_Read(b *testing.B) {
	const size = 10_000
	for _, shards := range shardCounts {
		b.Run(fmt.Sprintf("shards=%d", shards), func(b *testing.B) {
			c := preloadByteCacheWithShards(size, shards)
			var ops atomic.Int64
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					i := int(ops.Add(1))
					_, _ = c.Get(context.Background(), strconv.Itoa(i%size))
				}
			})
		})
	}
}

func BenchmarkByteCache_Shards_Parallel_Write(b *testing.B) {
	const size = 10_000
	val := []byte("v")
	for _, shards := range shardCounts {
		b.Run(fmt.Sprintf("shards=%d", shards), func(b *testing.B) {
			c := preloadByteCacheWithShards(size, shards)
			var ops atomic.Int64
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					i := int(ops.Add(1))
					_ = c.Set(context.Background(), strconv.Itoa(i%size), val, 0)
				}
			})
		})
	}
}

func BenchmarkByteCache_Shards_Parallel_Mixed(b *testing.B) {
	const size = 10_000
	val := []byte("v")
	for _, shards := range shardCounts {
		b.Run(fmt.Sprintf("shards=%d", shards), func(b *testing.B) {
			c := preloadByteCacheWithShards(size, shards)
			var ops atomic.Int64
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					i := int(ops.Add(1))
					key := strconv.Itoa(i % size)
					if i%10 < 8 {
						_, _ = c.Get(context.Background(), key)
					} else {
						_ = c.Set(context.Background(), key, val, 0)
					}
				}
			})
		})
	}
}

func BenchmarkByteCache_Shards_Serial_Set(b *testing.B) {
	const size = 10_000
	val := []byte("v")
	for _, shards := range shardCounts {
		b.Run(fmt.Sprintf("shards=%d", shards), func(b *testing.B) {
			c := NewByteCacheWithShards(int64(size)*64, shards, 0)
			b.ResetTimer()
			for i := range b.N {
				_ = c.Set(context.Background(), strconv.Itoa(i%size), val, 0)
			}
		})
	}
}

// ---------- RingCache ----------

func BenchmarkRingCache_Set(b *testing.B) {
	c := NewRingCache[string, string](b.N, 0)
	b.ResetTimer()
	for i := range b.N {
		_ = c.Set(context.Background(), strconv.Itoa(i), "value", 0)
	}
}

func BenchmarkRingCache_Get_Hit(b *testing.B) {
	const size = 10_000
	c := preloadRing()

	b.ResetTimer()
	for i := range b.N {
		_, _ = c.Get(context.Background(), strconv.Itoa(i%size))
	}
}

func BenchmarkRingCache_Overwrite(b *testing.B) {
	// Small ring forces constant overwrites.
	c := NewRingCache[string, string](100, 0)
	b.ResetTimer()
	for i := range b.N {
		_ = c.Set(context.Background(), strconv.Itoa(i), "v", 0)
	}
}

func BenchmarkRingCache_Parallel(b *testing.B) {
	const size = 10_000
	c := preloadRing()

	b.ResetTimer()
	var ops atomic.Int64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(ops.Add(1))
			key := strconv.Itoa(i % size)
			if i%10 < 8 {
				_, _ = c.Get(context.Background(), key)
			} else {
				_ = c.Set(context.Background(), key, "v", 0)
			}
		}
	})
}

// ---------- ChainCache ----------

func BenchmarkChainCache_Get_L1Hit(b *testing.B) {
	const size = 10_000
	l1 := preloadMemory(size)
	l2 := NewMemoryCache[string, string](size, 0)
	chain := NewChainCache[string, string](l1, l2, time.Minute)

	b.ResetTimer()
	for i := range b.N {
		_, _ = chain.Get(context.Background(), strconv.Itoa(i%size))
	}
}

func BenchmarkChainCache_Get_L2Promote(b *testing.B) {
	const size = 10_000
	l1 := NewMemoryCache[string, string](size, 0)
	l2 := preloadMemory(size)
	chain := NewChainCache[string, string](l1, l2, time.Minute)

	b.ResetTimer()
	for i := range b.N {
		_, _ = chain.Get(context.Background(), strconv.Itoa(i%size))
	}
}

func BenchmarkChainCache_Set(b *testing.B) {
	l1 := NewMemoryCache[string, string](b.N, 0)
	l2 := NewMemoryCache[string, string](b.N, 0)
	chain := NewChainCache[string, string](l1, l2, time.Minute)

	b.ResetTimer()
	for i := range b.N {
		_ = chain.Set(context.Background(), strconv.Itoa(i), "value", 0)
	}
}

func BenchmarkChainCache_Parallel(b *testing.B) {
	const size = 10_000
	l1 := preloadMemory(size)
	l2 := preloadMemory(size)
	chain := NewChainCache[string, string](l1, l2, time.Minute)

	b.ResetTimer()
	var ops atomic.Int64
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			i := int(ops.Add(1))
			key := strconv.Itoa(i % size)
			if i%10 < 8 {
				_, _ = chain.Get(context.Background(), key)
			} else {
				_ = chain.Set(context.Background(), key, "v", 0)
			}
		}
	})
}

// ---------- Cross-implementation comparison ----------

func BenchmarkComparison_Get(b *testing.B) {
	const size = 10_000
	mem := preloadMemory(size)
	bc := preloadByteCache(size)
	ring := preloadRing()

	b.Run("MemoryCache", func(b *testing.B) {
		for i := range b.N {
			_, _ = mem.Get(context.Background(), strconv.Itoa(i%size))
		}
	})
	b.Run("ByteCache", func(b *testing.B) {
		for i := range b.N {
			_, _ = bc.Get(context.Background(), strconv.Itoa(i%size))
		}
	})
	b.Run("RingCache", func(b *testing.B) {
		for i := range b.N {
			_, _ = ring.Get(context.Background(), strconv.Itoa(i%size))
		}
	})
}

func BenchmarkComparison_Set(b *testing.B) {
	b.Run("MemoryCache", func(b *testing.B) {
		c := NewMemoryCache[string, string](b.N, 0)
		b.ResetTimer()
		for i := range b.N {
			_ = c.Set(context.Background(), strconv.Itoa(i), "value", 0)
		}
	})
	b.Run("ByteCache", func(b *testing.B) {
		c := NewByteCache(int64(b.N)*64, 0)
		val := []byte("value")
		b.ResetTimer()
		for i := range b.N {
			_ = c.Set(context.Background(), strconv.Itoa(i), val, 0)
		}
	})
	b.Run("RingCache", func(b *testing.B) {
		c := NewRingCache[string, string](b.N, 0)
		b.ResetTimer()
		for i := range b.N {
			_ = c.Set(context.Background(), strconv.Itoa(i), "value", 0)
		}
	})
}

func BenchmarkComparison_Parallel_Mixed(b *testing.B) {
	const size = 10_000

	b.Run("MemoryCache", func(b *testing.B) {
		c := preloadMemory(size)
		var ops atomic.Int64
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				i := int(ops.Add(1))
				key := strconv.Itoa(i % size)
				if i%10 < 8 {
					_, _ = c.Get(context.Background(), key)
				} else {
					_ = c.Set(context.Background(), key, "v", 0)
				}
			}
		})
	})
	b.Run("ByteCache", func(b *testing.B) {
		c := preloadByteCache(size)
		var ops atomic.Int64
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				i := int(ops.Add(1))
				key := strconv.Itoa(i % size)
				if i%10 < 8 {
					_, _ = c.Get(context.Background(), key)
				} else {
					_ = c.Set(context.Background(), key, []byte("v"), 0)
				}
			}
		})
	})
	b.Run("RingCache", func(b *testing.B) {
		c := preloadRing()
		var ops atomic.Int64
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				i := int(ops.Add(1))
				key := strconv.Itoa(i % size)
				if i%10 < 8 {
					_, _ = c.Get(context.Background(), key)
				} else {
					_ = c.Set(context.Background(), key, "v", 0)
				}
			}
		})
	})
}

// ---------- Zipf (hot-key) workload ----------

func BenchmarkMemoryCache_Zipf(b *testing.B) {
	const size = 10_000
	c := preloadMemory(size)
	zipf := rand.NewZipf(rand.New(rand.NewPCG(1, 2)), 1.1, 1, size-1)

	b.ResetTimer()
	for range b.N {
		key := strconv.FormatUint(zipf.Uint64(), 10)
		if _, err := c.Get(context.Background(), key); err != nil {
			_ = c.Set(context.Background(), key, "v", 0)
		}
	}
}

func BenchmarkByteCache_Zipf(b *testing.B) {
	const size = 10_000
	c := preloadByteCache(size)
	zipf := rand.NewZipf(rand.New(rand.NewPCG(1, 2)), 1.1, 1, size-1)
	val := []byte("v")

	b.ResetTimer()
	for range b.N {
		key := strconv.FormatUint(zipf.Uint64(), 10)
		if _, err := c.Get(context.Background(), key); err != nil {
			_ = c.Set(context.Background(), key, val, 0)
		}
	}
}

// ---------- Value-size scaling ----------

func BenchmarkByteCache_ValueSize(b *testing.B) {
	for _, vsize := range []int{64, 256, 1024, 4096} {
		b.Run(fmt.Sprintf("%dB", vsize), func(b *testing.B) {
			val := make([]byte, vsize)
			c := NewByteCache(int64(10_000)*(int64(vsize)+10), 0)
			b.ResetTimer()
			for i := range b.N {
				_ = c.Set(context.Background(), strconv.Itoa(i%10_000), val, 0)
			}
		})
	}
}
