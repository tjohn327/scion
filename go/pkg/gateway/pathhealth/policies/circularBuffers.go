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

import "time"

type DurationBuffer struct {
	// nextPos is the next position to write a value into
	nextPos int
	// values holds the measurements
	values []time.Duration
}

func NewDurationBuffer(size int) *DurationBuffer {
	if size <= 1 {
		return nil
	}
	return &DurationBuffer{nextPos: 0, values: make([]time.Duration, size)}
}

func (d DurationBuffer) GetSize() int {
	return len(d.values)
}

func (d DurationBuffer) GetLastValue() time.Duration {
	prevPos := (d.nextPos + len(d.values) - 1) % len(d.values)
	return d.values[prevPos]
}

func (d DurationBuffer) GetAllValues() []time.Duration {
	return d.values
}

func (d *DurationBuffer) AddValue(val time.Duration) {
	d.values[d.nextPos] = val
	d.nextPos = (d.nextPos + 1) % len(d.values)
}

func (d DurationBuffer) GetMeanValue() time.Duration {
	sum := 0.0
	for _, e := range d.values {
		sum += float64(e)
	}
	return time.Duration((sum / float64(len(d.values))))
}

/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////

type Float64Buffer struct {
	// nextPos is the next position to write a value into
	nextPos int
	// values holds the measurements
	values []float64
}

func NewFloat64Buffer(size int) *Float64Buffer {
	if size <= 1 {
		return nil
	}
	return &Float64Buffer{nextPos: 0, values: make([]float64, size)}
}

func (f Float64Buffer) GetSize() int {
	return len(f.values)
}

func (f Float64Buffer) GetLastValue() float64 {
	prevPos := (f.nextPos + len(f.values) - 1) % len(f.values)
	return f.values[prevPos]
}

func (f Float64Buffer) GetAllValues() []float64 {
	return f.values
}

func (f *Float64Buffer) AddValue(val float64) {
	f.values[f.nextPos] = val
	f.nextPos = (f.nextPos + 1) % len(f.values)
}

func (f Float64Buffer) GetMeanValue() float64 {
	sum := 0.0
	for _, e := range f.values {
		sum += e
	}
	return sum / float64(len(f.values))
}

/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////

type Int64Buffer struct {
	// nextPos is the next position to write a value into
	nextPos int
	// values holds the measurements
	values []int64
}

func NewInt64Buffer(size int) *Int64Buffer {
	if size <= 1 {
		return nil
	}
	return &Int64Buffer{nextPos: 0, values: make([]int64, size)}
}

func (i Int64Buffer) GetSize() int {
	return len(i.values)
}

func (i Int64Buffer) GetLastValue() int64 {
	prevPos := (i.nextPos + len(i.values) - 1) % len(i.values)
	return i.values[prevPos]
}

func (i Int64Buffer) GetAllValues() []int64 {
	return i.values
}

func (i *Int64Buffer) AddValue(val int64) {
	i.values[i.nextPos] = val
	i.nextPos = (i.nextPos + 1) % len(i.values)
}

func (i Int64Buffer) GetMeanValue() float64 {
	sum := 0.0
	for _, e := range i.values {
		sum += float64(e)
	}
	return sum / float64(len(i.values))
}
