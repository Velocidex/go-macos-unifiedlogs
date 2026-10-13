package unifiedlogs

const (
	firehoseChunk   uint32 = 0x6001
	oversizeChunk   uint32 = 0x6002
	statedumpChunk  uint32 = 0x6003
	simpledumpChunk uint32 = 0x6004

	chunkPreambleSize = 16 // Include preamble size in total chunk size
	headerChunk       = 0x1000
	catalogChunk      = 0x600b
	chunksetChunk     = 0x600d
)
