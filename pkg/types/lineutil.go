package types

// ComputeLineColumn computes line and column numbers from a byte offset in content.
// Lines and columns are 1-indexed (first line is 1, first column is 1).
func ComputeLineColumn(content []byte, byteOffset int) (line, column int) {
	line = 1
	column = 1
	for i := 0; i < byteOffset && i < len(content); i++ {
		if content[i] == '\n' {
			line++
			column = 1
		} else {
			column++
		}
	}
	return line, column
}
