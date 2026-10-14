package unifiedlogs

import (
	"context"
	"errors"
	"io"

	"github.com/alitto/pond/v2"
)

func ReadAllWithLimit(fd io.Reader, limit int) ([]byte, error) {
	// If we reach the limit signal this as an error!
	res, err := io.ReadAll(io.LimitReader(fd, int64(limit)))
	if len(res) >= limit {
		return res, errors.New("MemoryBufferExceeded")
	}

	return res, err
}

type UnifiedLogParser struct {
	provider          FileProvider
	logger            *Logger
	cache             StringCache
	threads           int
	message_formatter *MessageFormatter
}

type ParserOptions struct {
	Threads int
}

func NewUnifiedLogParser(
	provider FileProvider,
	logger *Logger,
	cache StringCache, opts ...ParserOptions) *UnifiedLogParser {
	res := &UnifiedLogParser{
		provider:          provider,
		logger:            logger,
		cache:             cache,
		threads:           5,
		message_formatter: NewMessageFormatter(logger),
	}
	for _, opt := range opts {
		if opt.Threads > 0 {
			res.threads = opt.Threads
		}
	}
	return res
}

func (self *UnifiedLogParser) Parse(
	ctx context.Context) (chan LogData, error) {

	timesyncData, err := CollectTimesync(self.provider)
	if err != nil {
		return nil, err
	}

	output_chan := make(chan LogData)
	go func() {
		defer close(output_chan)

		pool := pond.NewPool(self.threads,
			pond.WithContext(ctx),
			pond.WithQueueSize(2))
		defer pool.StopAndWait()

		for _, entry := range self.provider.Tracev3Files() {
			r, err := entry.Reader()
			if err != nil {
				self.logger.Printf("%v", err)
				continue
			}

			it := &UnifiedLogIterator{
				Reader:   r,
				Evidence: entry.SourcePath(),
				Logger:   self.logger,
			}
			for {
				chunk, ok := it.Next()
				if !ok {
					break
				}

				pool.Submit(func() {
					logs, missing := self.BuildLog(
						chunk, timesyncData, true)
					for _, l := range logs {
						select {
						case <-ctx.Done():
							return
						case output_chan <- l:
						}

					}
					_ = missing
				})
			}
		}
	}()

	return output_chan, nil
}
