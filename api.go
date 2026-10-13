package unifiedlogs

import (
	"context"
	"errors"
	"io"

	"github.com/alitto/pond/v2"
	lru "github.com/hashicorp/golang-lru/v2"
)

const (
	MAX_MEMORY_LARGE = 1000 * 1024 * 1024
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
	message_formatter *MessageFormatter
}

func NewUnifiedLogParser(
	provider FileProvider,
	logger *Logger,
	cache StringCache) *UnifiedLogParser {
	res := &UnifiedLogParser{
		provider:          provider,
		logger:            logger,
		cache:             cache,
		message_formatter: NewMessageFormatter(logger),
	}
	res.message_formatter.lru, _ = lru.New[string, []string](1000)
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

		pool := pond.NewPool(20)
		defer pool.StopAndWait()

		for _, entry := range self.provider.Tracev3Files() {
			r, err := entry.Reader()
			if err != nil {
				self.logger.Printf("%v", err)
				continue
			}

			/*
					data, err := ReadAllWithLimit(r, MAX_MEMORY_LARGE)
					r.Close()
					if err != nil {
						self.logger.Printf("%v", err)
						continue
					}


				fmt.Printf("File %v is %v\n",
					entry.SourcePath(), len(data))
			*/

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
