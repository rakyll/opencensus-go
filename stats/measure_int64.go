// Copyright 2017, OpenCensus Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package stats

// MeasureInt64 is a measure of type int64.
type MeasureInt64 struct {
	name        string
	unit        string
	description string
	views       map[*View]bool
}

// NewMeasureInt64 creates a new measure of type MeasureInt64. It returns an
// error if a measure with the same name already exists.
func NewMeasureInt64(name, description, unit string) (*MeasureInt64, error) {
	m := &MeasureInt64{
		name:        name,
		description: description,
		unit:        unit,
		views:       make(map[*View]bool),
	}

	req := &registerMeasureReq{
		m:   m,
		err: make(chan error),
	}
	defaultWorker.c <- req
	if err := <-req.err; err != nil {
		return nil, err
	}

	return m, nil
}

// Name returns the name of the measure.
func (m *MeasureInt64) Name() string {
	return m.name
}

// Unit returns the unit of the measure.
func (m *MeasureInt64) Unit() string {
	return m.unit
}

func (m *MeasureInt64) addView(v *View) {
	m.views[v] = true
}

func (m *MeasureInt64) removeView(v *View) {
	delete(m.views, v)
}

func (m *MeasureInt64) viewsCount() int { return len(m.views) }

// M creates a new int64 measurement.
func (m *MeasureInt64) M(v int64) Measurement {
	return &measurementInt64{
		m: m,
		v: v,
	}
}

type measurementInt64 struct {
	m *MeasureInt64
	v int64
}

func (mi *measurementInt64) isMeasurement() bool { return true }
