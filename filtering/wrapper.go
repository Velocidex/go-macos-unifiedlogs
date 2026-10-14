package filtering

import (
	unifiedlogs "github.com/Velocidex/go-macos-unifiedlogs"
)

func WrapLogData(log *unifiedlogs.LogData) *unifiedlogs.LogData {
	return log
}
