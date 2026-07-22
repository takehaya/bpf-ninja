// Package dslvocab caches the parsed bundled protocol vocabulary.
//
// Lives in its own package so both the production Compile facade and
// the resolver's tests can share one sync.Once without a cycle through
// the dsl package. Keeping the embed.FS in the protocols package and
// vocab types in vocab keeps this layer a pure consumer.
package dslvocab

import (
	"sync"

	"github.com/takehaya/bpf-ninja/pkg/kunai/protocols"
	"github.com/takehaya/bpf-ninja/pkg/kunai/vocab"
)

// Bundled returns the loaded vocabulary, memoized on first success.
// Callers must not mutate the returned map.
func Bundled() (map[string]*vocab.ProtocolSpec, error) {
	once.Do(func() {
		data, err = vocab.Load(protocols.FS, ".")
	})
	return data, err
}

var (
	once sync.Once
	data map[string]*vocab.ProtocolSpec
	err  error
)
