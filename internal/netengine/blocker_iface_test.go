package netengine

// Compile-time check: the Linux engine implements local block recovery.
var (
	_ BlockerEngine     = (*LinuxEngine)(nil)
	_ WorkingStateSaver = (*LinuxEngine)(nil)
)
