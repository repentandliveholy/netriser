//go:build darwin

package netengine

var (
	_ BlockerEngine     = (*DarwinEngine)(nil)
	_ WorkingStateSaver = (*DarwinEngine)(nil)
	_ LocalProber       = (*DarwinEngine)(nil)
)
