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

package policies

import (
	"github.com/scionproto/scion/go/lib/snet"
)

type PathMode int

const (
	Normal PathMode = iota
	MultiPath
	AdaptiveMultiPath
)

type PathPolicy interface {
	Filter(paths []snet.Path) []snet.Path
}

type PerfPolicy interface {
	// Better is a function that takes two paths and decides whether the first
	// one is "better" according to the policy.
	Better(x, y *Stats) bool
}

type PathPerfWeights struct {
	Latency   float64
	Bandwidth float64
	Jitter    float64
	DropRate  float64
}

// Stats contains all the metrics about a path.
type Stats struct {
	// Fingerprint is unique ID of the path. It can be used to achieve consistent ordering
	// and thus prevent random path switching even if all the other path metrics are the same.
	Fingerprint snet.PathFingerprint

	// Metrics keeps track of the last n path metrics measures
	Metrics

	// Is Alive is true if the probes are passing through at the moment.
	IsAlive bool
	// IsCurrent is true when the path is currently the active one.
	IsCurrent bool
	// IsRevoked is true if a revocation was issued for one or more interfaces on the path.
	IsRevoked bool

	NormalizedMetrics NormalizedMetrics
}

type NormalizedMetrics struct {
	Latency   float64
	Jitter    float64
	DropRate  float64
	Bandwidth float64
	Score     float64
}

// NewStats construct a new Stats struct and poplulates it initially as needed.
func NewStats(fp snet.PathFingerprint) Stats {

	historyLen := 100

	return Stats{
		Fingerprint: fp,
		Metrics: Metrics{
			Latencies:  NewDurationBuffer(historyLen),
			Jitters:    NewDurationBuffer(historyLen),
			DropRates:  NewFloat64Buffer(historyLen),
			Bandwidths: NewInt64Buffer(historyLen),
		},
		IsAlive:   false,
		IsCurrent: false,
		IsRevoked: false,
	}
}

// keeps a history of the last few measurements for each metric
type Metrics struct {
	// Latency is median one-way latency of the path.
	Latencies *DurationBuffer
	// Jitter is the average of the difference between consecutive latencies.
	Jitters *DurationBuffer
	// DropRate is a percentage of probes with no replies. From interval (0,1).
	DropRates *Float64Buffer
	// Bandwidth is the bandwidth of the path in bps
	Bandwidths *Int64Buffer
}

// Policies is a container for different kinds of policies.
type Policies struct {
	// Path policies are used to determine which paths are eligible and which are not.
	PathPolicy PathPolicy
	// PerfPolicy determines how to select a path if there are several eligible
	// ones. If set to nil, arbitrary path is chosen.
	PerfPolicy PerfPolicy
	// PathCount is the max number of paths to return to the user. Defaults to 1.
	PathCount int

	Mode PathMode
}
