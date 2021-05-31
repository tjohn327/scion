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
	"time"

	"github.com/scionproto/scion/go/lib/snet"
	"github.com/scionproto/scion/go/pkg/gateway/pathhealth/policies"
)

const (
	// rejectedInfo is a string to log about dead paths.
	deadInfo = "dead (probes are not passing through)"
	// rejectedInfo is a string to log about paths rejected by path policies.
	rejectedInfo = "rejected by path policy"

	maxLatency   float64 = float64(250 * time.Millisecond)
	maxJitter    float64 = float64(200 * time.Millisecond)
	maxDropRate  float64 = 1
	maxBandwidth float64 = 1000

	duplicateThresholdLatency  float64 = 2
	duplicateThresholdJitter   float64 = 2.25
	duplicateThresholdDropRate float64 = 1.5
)

const (
	Normal = iota
	MultiPath
	AdaptiveMultiPath
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

	Mode policies.PathMode
}

type Allowed struct {
	Fingerprint snet.PathFingerprint
	Path        snet.Path
	Stats       policies.Stats
	Selectable  Selectable
}

func setNormalizedMetrics(allowed []Allowed) {
	length := len(allowed)
	for i := 0; i < length; i++ {
		allowed[i].Stats.NormalizedMetrics = policies.NormalizedMetrics{
			Latency:   float64(allowed[i].Stats.Latencies.GetLastValue().Nanoseconds()) / maxLatency,
			Jitter:    float64(allowed[i].Stats.Jitters.GetLastValue().Nanoseconds()) / maxJitter,
			DropRate:  allowed[i].Stats.DropRates.GetLastValue() / maxDropRate,
			Bandwidth: float64(allowed[i].Stats.Bandwidths.GetLastValue()) / maxBandwidth,
		}
	}
}

// func setNormalizedMetrics(allowed []Allowed) {
// 	length := len(allowed)
// 	latencies := make([]float64, length)
// 	jitters := make([]float64, length)
// 	dropRates := make([]float64, length)
// 	bandwidths := make([]float64, length)
// 	// scores := make([]float64, length)
// 	for i := 0; i < length; i++ {
// 		latencies[i] = float64(allowed[i].Stats.Latencies.GetLastValue().Nanoseconds())
// 		jitters[i] = float64(allowed[i].Stats.Jitters.GetLastValue().Nanoseconds())
// 		dropRates[i] = allowed[i].Stats.DropRates.GetLastValue()
// 		bandwidths[i] = float64(allowed[i].Stats.Bandwidths.GetLastValue())
// 	}
// 	normalizeSlice(latencies, maxLatency)
// 	normalizeSlice(jitters, maxJitter)
// 	normalizeSlice(dropRates, maxDropRate)
// 	normalizeSlice(bandwidths, maxBandwidth)
// 	for i := 0; i < length; i++ {
// 		allowed[i].Stats.NormalizedMetrics.Latency = latencies[i]
// 		allowed[i].Stats.NormalizedMetrics.Jitter = jitters[i]
// 		allowed[i].Stats.NormalizedMetrics.DropRate = dropRates[i]
// 		allowed[i].Stats.NormalizedMetrics.Bandwidth = bandwidths[i]
// 	}
// }

func normalizeSlice(slice []float64, max float64) {
	if max == 0 {
		max = getMax(slice)
	}
	if max == 0 {
		for i := range slice {
			slice[i] = 0
		}
	} else {
		for i := range slice {
			slice[i] = slice[i] / max
		}
	}
}

func getMax(slice []float64) float64 {
	var max float64 = 0
	for i := range slice {
		if slice[i] > max {
			max = slice[i]
		}
	}
	return max
}

// Select selects the best paths.
func (f *FilteringPathSelector) Select(selectables []Selectable, current FingerprintSet) Selection {

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
	setNormalizedMetrics(allowed)

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

	// for _, v := range allowed {
	// 	fmt.Println(v.Fingerprint, v.Stats.NormalizedMetrics.Score)
	// }

	// fmt.Println()

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

	var currentPaths []Allowed
	for _, a := range allowed {
		if a.Stats.IsCurrent {
			currentPaths = append(currentPaths, a)
		}
	}

	if f.Mode == AdaptiveMultiPath && len(currentPaths) > 0 {

		meanLatency := currentPaths[0].Stats.Latencies.GetMeanValue()
		meanDropRate := currentPaths[0].Stats.DropRates.GetMeanValue()
		meanJitter := currentPaths[0].Stats.Jitters.GetMeanValue()
		currentLatency := currentPaths[0].Stats.Latencies.GetLastValue()
		currentDropRate := currentPaths[0].Stats.DropRates.GetLastValue()
		currentJitter := currentPaths[0].Stats.Jitters.GetLastValue()

		duplicate := false

		if currentLatency > time.Duration(float64(meanLatency)*duplicateThresholdLatency) {
			duplicate = true
		}
		if currentDropRate > meanDropRate*duplicateThresholdDropRate {
			duplicate = true
		}
		if currentJitter > time.Duration(float64(meanJitter)*duplicateThresholdJitter) {
			duplicate = true
		}

		if duplicate {
			pathCount = 2
		} else {
			pathCount = 1
		}

	}

	if pathCount > len(allowed) {
		pathCount = len(allowed)
	}

	paths := make([]snet.Path, 0, pathCount)

	// if pathCount == 1 && !allowed[0].Stats.IsCurrent && len(currentPaths) > 0 {
	// 	if currentPaths[0].Stats.NormalizedMetrics.Score <=
	// 		allowed[0].Stats.NormalizedMetrics.Score*1.2 {
	// 		paths = append(paths, currentPaths[0].Path)
	// 	}
	// }

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
