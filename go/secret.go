package samp

type Seed struct{ b [32]byte }

func SeedFromBytes(b [32]byte) Seed { return Seed{b} }

// ExposeSecret returns the raw 32 bytes. Every caller of this method is an
// audit point: it is the only way to reach seed material.
func (s Seed) ExposeSecret() [32]byte { return s.b }

func (s Seed) String() string { return "Seed([REDACTED])" }

type ContentKey struct{ b [32]byte }

func ContentKeyFromBytes(b [32]byte) ContentKey { return ContentKey{b} }
func (c ContentKey) ExposeSecret() [32]byte     { return c.b }
func (c ContentKey) String() string             { return "ContentKey([REDACTED])" }

type ViewScalar struct{ b [32]byte }

func ViewScalarFromBytes(b [32]byte) ViewScalar { return ViewScalar{b} }
func (v ViewScalar) ExposeSecret() [32]byte     { return v.b }
func (v ViewScalar) String() string             { return "ViewScalar([REDACTED])" }
