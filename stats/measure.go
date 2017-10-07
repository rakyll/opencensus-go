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

// Measure is the interface for all measure types. A measure is required when
// defining a view.
type Measure interface {
	Name() string
	addView(v View)
	removeView(v View)
	viewsCount() int
}

// Measurement is the numeric value measured when recording stats. Each measure
// provides methods to create measurements of their kind. For example, MeasureInt64
// provides M to convert an int64 into a measurement.
type Measurement interface {
	isMeasurement() bool
}

// MeasureByName returns the registered measure associated with name.
func MeasureByName(name string) (Measure, error) {
	req := &getMeasureByNameReq{
		name: name,
		c:    make(chan *getMeasureByNameResp),
	}
	defaultWorker.c <- req
	resp := <-req.c
	return resp.m, resp.err
}

// DeleteMeasure deletes an existing measure to allow for creation of a new
// measure with the same name. It returns an error if the measure cannot be
// deleted (if one or multiple registered views refer to it).
func DeleteMeasure(m Measure) error {
	req := &deleteMeasureReq{
		m:   m,
		err: make(chan error),
	}
	defaultWorker.c <- req
	return <-req.err
}
