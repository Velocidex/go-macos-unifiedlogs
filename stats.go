package unifiedlogs

import "sync/atomic"

var gStats Stats

type Stats struct {
	DecompressedChunks int64
	FileReads          int64
	CursorReads        int64
	CursorSeeks        int64
	BufioGet           int64
	BufioPut           int64
}

func GetStats() Stats {
	res := Stats{
		DecompressedChunks: atomic.LoadInt64(&gStats.DecompressedChunks),
		FileReads:          atomic.LoadInt64(&gStats.FileReads),
		CursorReads:        atomic.LoadInt64(&gStats.CursorReads),
		CursorSeeks:        atomic.LoadInt64(&gStats.CursorSeeks),
		BufioGet:           atomic.LoadInt64(&gStats.BufioGet),
		BufioPut:           atomic.LoadInt64(&gStats.BufioPut),
	}
	return res
}

func ResetStats() {
	atomic.StoreInt64(&gStats.DecompressedChunks, 0)
	atomic.StoreInt64(&gStats.FileReads, 0)
	atomic.StoreInt64(&gStats.CursorReads, 0)
	atomic.StoreInt64(&gStats.CursorSeeks, 0)
	atomic.StoreInt64(&gStats.BufioGet, 0)
	atomic.StoreInt64(&gStats.BufioPut, 0)
}
