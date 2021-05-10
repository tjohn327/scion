// Copyright 2020 Anapaya Systems
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

package pathhealth

import (
	"fmt"
	"sort"
	"strings"

	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/pkg/gateway/pathhealth/policies"
)

const (
	// rejectedInfo is a string to log about dead paths.
	deadInfo = "dead (probes are not passing through)"
	// rejectedInfo is a string to log about paths rejected by path policies.
	rejectedInfo = "rejected by path policy"
)

// PathPolicy filters the set of paths.
type PathPolicy interface {
	Filter(paths []snet.Path) []snet.Path
}

type PerfPolicy interface {
	// Better is a function that takes two paths and decides whether the first
	// one is "better" according to the policy.
	Better(x, y *policies.Stats) bool
}

// FilteringPathSelector selects the best paths from a filtered set of paths.
type FilteringPathSelector struct {
	// PathPolicy is used to determine which paths are eligible and which are not.
	PathPolicy PathPolicy
	// PerfPolicy determines how to select a path if there are several eligible
	PerfPolicy PerfPolicy
	// RevocationStore keeps track of the revocations.
	RevocationStore
	// PathCount is the max number of paths to return to the user. Defaults to 1.
	PathCount int
}

// Select selects the best paths.
func (f *FilteringPathSelector) Select(selectables []Selectable, current FingerprintSet) Selection {
	type Allowed struct {
		Fingerprint snet.PathFingerprint
		Path        snet.Path
		Stats       policies.Stats
		Selectable  Selectable
	}

	// Sort out the paths allowed by the path policy.
	var allowed []Allowed
	var dead []snet.Path
	var rejected []snet.Path
	for _, selectable := range selectables {
		path := selectable.Path()
		if !isPathAllowed(f.PathPolicy, path) {
			rejected = append(rejected, path)
			continue
		}

		// state := selectable.State()
		stats := selectable.Stats()
		if !stats.IsAlive {
			dead = append(dead, path)
			continue
		}
		fingerprint := snet.Fingerprint(path)
		_, isCurrent := current[fingerprint]
		stats.IsCurrent = isCurrent
		stats.IsRevoked = f.RevocationStore.IsRevoked(path)
		allowed = append(allowed, Allowed{
			Path:        path,
			Stats:       stats,
			Fingerprint: fingerprint,
		})
	}
	// Sort the allowed paths according the the perf policy.
	sort.SliceStable(allowed, func(i, j int) bool {
		// If some of the paths are alive (probes are passing through), yet still revoked
		// prefer the non-revoked paths as the revoked ones may be flaky.
		switch {
		case allowed[i].Stats.IsRevoked && !allowed[j].Stats.IsRevoked:
			return false
		case !allowed[i].Stats.IsRevoked && allowed[j].Stats.IsRevoked:
			return true
		}

		if f.PerfPolicy != nil {
			return f.PerfPolicy.Better(&allowed[i].Stats, &allowed[j].Stats)
		}

		if shorter, ok := isShorter(allowed[i].Path, allowed[j].Path); ok {
			return shorter
		}
		return allowed[i].Fingerprint > allowed[j].Fingerprint
	})

	// Make the info string.
	var format = "      %-44s %s"
	info := make([]string, 0, len(selectables)+1)
	info = append(info, fmt.Sprintf(format, "STATE", "PATH"))
	for _, a := range allowed {
		var state string
		if a.Stats.IsCurrent {
			state = "-->"
		}
		info = append(info, fmt.Sprintf(format, state, a.Path))
	}
	for _, path := range dead {
		info = append(info, fmt.Sprintf(format, deadInfo, path))
	}
	for _, path := range rejected {
		info = append(info, fmt.Sprintf(format, rejectedInfo, path))
	}

	pathCount := f.PathCount
	if pathCount == 0 {
		pathCount = 1
	}
	if pathCount > len(allowed) {
		pathCount = len(allowed)
	}

	paths := make([]snet.Path, 0, pathCount)
	for i := 0; i < pathCount; i++ {
		paths = append(paths, allowed[i].Path)
	}
	return Selection{
		Paths:         paths,
		Info:          strings.Join(info, "\n"),
		PathsAlive:    len(allowed),
		PathsDead:     len(dead),
		PathsRejected: len(rejected),
	}
}

// isPathAllowed returns true if path is allowed by the policy.
func isPathAllowed(policy PathPolicy, path snet.Path) bool {
	if policy == nil {
		return true
	}
	return len(policy.Filter([]snet.Path{path})) > 0
}

func isShorter(a, b snet.Path) (bool, bool) {
	mA, mB := a.Metadata(), b.Metadata()
	if mA == nil || mB == nil {
		return false, false
	}
	if lA, lB := len(mA.Interfaces), len(mB.Interfaces); lA != lB {
		return lA < lB, true
	}
	return false, false
}
