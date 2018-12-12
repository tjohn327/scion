// Copyright 2018 ETH Zurich
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package syncresv provides primitives for a SIBRA extension store
// which allows atomic updates of the extensions.
package syncresv

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/scionproto/scion/go/lib/common"
	"github.com/scionproto/scion/go/lib/sibra/sbextn"
)

// Store holds a Data value which is updated atomically.
type Store struct {
	value atomic.Value
	// Used to avoid races between multiple writers
	mutex sync.Mutex
}

func NewStore(ephem *sbextn.Ephemeral, steady *sbextn.Steady) *Store {
	sp := &Store{}
	now := time.Now()
	sp.value.Store(
		&Data{
			Ephemeral:   ephem,
			Steady:      steady,
			ModifyTime:  now,
			RefreshTime: now,
		},
	)
	return sp
}

// UpdateEphem updates the ephemeral extension of the snapshot.
func (sp *Store) UpdateEphem(ephem *sbextn.Ephemeral) {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()
	value := sp.Load()
	value.RefreshTime = time.Now()
	value.ModifyTime = value.RefreshTime
	value.Ephemeral = ephem
	sp.value.Store(value)
}

// UpdateSteady updates the steady extension of the snapshot.
func (sp *Store) UpdateSteady(steady *sbextn.Steady) {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()
	value := sp.Load()
	value.RefreshTime = time.Now()
	value.ModifyTime = value.RefreshTime
	value.Steady = steady
	sp.value.Store(value)
}

// Update updates both steady and ephemeral extension of the snapshot.
func (sp *Store) Update(ephem *sbextn.Ephemeral, steady *sbextn.Steady) {
	sp.mutex.Lock()
	defer sp.mutex.Unlock()
	value := sp.Load()
	value.RefreshTime = time.Now()
	value.Ephemeral = ephem
	value.ModifyTime = value.RefreshTime
	value.Steady = steady
	sp.value.Store(value)
}

// Load returns a copy of the snapshot.
func (sp *Store) Load() *Data {
	val := *sp.value.Load().(*Data)
	return &val
}

// Data is the atomic value inside a Store object. It provides a
// snapshot of the extensions. Callers must not change the contents
// of the extensions.
type Data struct {
	Ephemeral   *sbextn.Ephemeral
	Steady      *sbextn.Steady
	ModifyTime  time.Time
	RefreshTime time.Time
}

// GetExtn returns the SIBRA extension that shall be used. The second
// return value indicates if a regular SCION path must be added to the
// packet in order for it to be forwarded correctly.
func (s Data) GetExtn() (common.Extension, bool) {
	if s.Ephemeral != nil && s.Ephemeral.Expiry().After(time.Now()) {
		return s.Ephemeral, false
	}
	if s.Steady != nil && s.Steady.Expiry().After(time.Now()) {
		return s.Steady, s.Steady.Setup
	}
	return nil, true
}