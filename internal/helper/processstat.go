package helper

import (
	"errors"
	"strconv"
	"strings"
)

// parseProcessStat extracts the state and field-22 start tick count from bounded
// procfs text. The last parenthesis closes comm, which may itself contain spaces
// and parentheses. Missing fields or nonnumeric start ticks fail without echoing data.
func parseProcessStat(data []byte) (string, bool, error) {
	if len(data) > 64*1024 {
		return "", false, errors.New("oversized process record")
	}
	end := strings.LastIndexByte(string(data), ')')
	if end < 0 {
		return "", false, errors.New("invalid process record")
	}
	fields := strings.Fields(string(data[end+1:]))
	if len(fields) < 20 || len(fields[0]) != 1 {
		return "", false, errors.New("incomplete process record")
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", false, errors.New("invalid start time")
	}
	return fields[19], fields[0] == "Z" || fields[0] == "X", nil
}
