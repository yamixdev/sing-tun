package tun

// Fragments start on eight-byte boundaries. Non-final fragments also end on
// that boundary, so a fixed cell bitmap is sufficient without storing ranges.
type fragmentCoverage struct {
	cells [128]uint64
}

func validFragmentRange(offset, length int, more bool) bool {
	return offset >= 0 && offset%8 == 0 && length > 0 && length <= 65535 &&
		offset <= 65535-length && (!more || length%8 == 0)
}

func (c *fragmentCoverage) add(offset, length int, more bool) bool {
	if !validFragmentRange(offset, length, more) {
		return false
	}
	for cell, end := offset/8, (offset+length+7)/8; cell < end; cell++ {
		c.cells[cell/64] |= uint64(1) << (cell % 64)
	}
	return true
}

func (c *fragmentCoverage) complete(total int) bool {
	if total <= 0 || total > 65535 {
		return false
	}
	count := (total + 7) / 8
	for word := 0; word < count/64; word++ {
		if c.cells[word] != ^uint64(0) {
			return false
		}
	}
	if remainder := count % 64; remainder != 0 {
		mask := uint64(1)<<remainder - 1
		return c.cells[count/64]&mask == mask
	}
	return true
}
