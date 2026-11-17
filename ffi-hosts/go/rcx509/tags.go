package rcx509

import (
	"slices"
	"strings"
)

// SetHostTags replaces the full set of host tags reported for this client.
//
// Tags use the usual "key:value" format. They are trimmed, empty tags are
// dropped, and duplicates are removed; a call with the same set as the last
// successful one does nothing.
func (c *Client) SetHostTags(tags []string) error {
	normalized := normalizeTags(tags)

	c.hostTagsMu.Lock()
	defer c.hostTagsMu.Unlock()

	// normalizeTags never returns nil, so a nil hostTags means no set has been
	// accepted yet, and an empty first set is still passed on.
	if c.hostTags != nil && slices.Equal(c.hostTags, normalized) {
		return nil
	}
	if err := c.ffiCtx.SetHostTags(normalized); err != nil {
		return err
	}
	c.hostTags = normalized
	return nil
}

// normalizeTags returns tags trimmed, without empty entries, sorted and
// deduplicated, so that two sets with the same content compare equal.
func normalizeTags(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag = strings.TrimSpace(tag); tag != "" {
			out = append(out, tag)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}
