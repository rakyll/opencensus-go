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

import (
	"bytes"
	"fmt"
	"reflect"
	"sync/atomic"
	"time"

	"go.opencensus.io/tag"
)

// View allows users to filter and aggregate the recorded events
// over a time window. Each view has to be registered to enable
// data retrieval. Use NewView to initiate new views.
// Unregister views once you don't want to collect any more events.
type View struct {
	name        string // name of View. Must be unique.
	description string

	// tagKeys to perform the aggregation on.
	tagKeys []tag.Key

	// Examples of measures are cpu:tickCount, diskio:time...
	m Measure

	// start is time when view collection was started originally.
	start time.Time

	forced     uint32 // 1 if view should collect data if no one is subscribed, use atomic to access
	subscribed uint32 // 1 if someone is subscribed and data need to be exported, use atomic to access

	collector *collector
}

// NewView creates a new view with the given name and description.
// View names need to be unique globally in the entire system.
//
// Data collection will only filter measurements recorded by the given keys.
// Collected data will be processed by the given aggregation algorithm for
// the given time window.
//
// Views need to be registered via RegisterView, or subscribed to, or need to be force
// collected to retrieve collection data. Once the view is no longer required,
// view can be unregistered.
func NewView(name, description string, keys []tag.Key, measure Measure, agg Aggregation, window Window) *View {
	return &View{
		name:        name,
		description: description,
		tagKeys:     keys,
		m:           measure,
		start:       time.Time{},
		collector:   &collector{make(map[string]aggregator), agg, window},
	}
}

// Name returns the name of the view.
func (v *View) Name() string {
	return v.name
}

// Description returns the name of the view.
func (v *View) Description() string {
	return v.description
}

func (v *View) startForcedCollection() {
	atomic.StoreUint32(&v.forced, 1)
}

func (v *View) stopForcedCollection() {
	atomic.StoreUint32(&v.forced, 0)
}

func (v *View) subscribe() {
	atomic.StoreUint32(&v.subscribed, 1)
}

func (v *View) unsubscribe() {
	atomic.StoreUint32(&v.subscribed, 0)
}

// isCollecting returns true if the view is exporting data
// by subscription or enabled for force collection.
func (v *View) isCollecting() bool {
	return atomic.LoadUint32(&v.subscribed) == 1 || atomic.LoadUint32(&v.forced) == 1
}

// isSubscribed returns true if the view is exporting
// data by subscription.
func (v *View) isSubscribed() bool {
	return atomic.LoadUint32(&v.subscribed) == 1
}

func (v *View) clearRows() {
	v.collector.clearRows()
}

// Window returns the timing window being used to collect
// metrics from this view.
func (v *View) Window() Window {
	return v.collector.w
}

// Aggregation returns the data aggregation method used to aggregate
// the measurements collected by this view.
func (v *View) Aggregation() Aggregation {
	return v.collector.a
}

// Measure returns the measure the view is collecting measurements for.
func (v *View) Measure() Measure {
	return v.m
}

func (v *View) collectedRows(now time.Time) []*Row {
	return v.collector.collectedRows(v.tagKeys, now)
}

func (v *View) addSample(m *tag.Map, val interface{}, now time.Time) {
	if !v.isCollecting() {
		return
	}
	sig := string(tag.EncodeOrderedTags(m, v.tagKeys))
	v.collector.addSample(sig, val, now)
}

// A ViewData is a set of rows about usage of the single measure associated
// with the given view during a particular window. Each row is specific to a
// unique set of tags.
type ViewData struct {
	View       *View
	Start, End time.Time
	Rows       []*Row
}

// Row is the collected value for a specific set of key value pairs a.k.a tags.
type Row struct {
	Tags             []tag.Tag
	AggregationValue AggregationData
}

func (r *Row) String() string {
	var buffer bytes.Buffer
	buffer.WriteString("{ ")
	buffer.WriteString("{ ")
	for _, t := range r.Tags {
		buffer.WriteString(fmt.Sprintf("{%v %v}", t.Key.Name(), t.Key.ValueToString(t.Value)))
	}
	buffer.WriteString(" }")
	buffer.WriteString(fmt.Sprintf("%v", r.AggregationValue))
	buffer.WriteString(" }")
	return buffer.String()
}

// Equal returns true if both Rows are equal. Tags are expected to be ordered
// by the key name. Even both rows have the same tags but the tags appear in
// different orders it will return false.
func (r *Row) Equal(other *Row) bool {
	if r == other {
		return true
	}

	return reflect.DeepEqual(r.Tags, other.Tags) && r.AggregationValue.equal(other.AggregationValue)
}

// ContainsRow returns true if rows contain r.
func ContainsRow(rows []*Row, r *Row) bool {
	for _, x := range rows {
		if r.Equal(x) {
			return true
		}
	}
	return false
}

// EqualRows returns true if rows1 and rows2 contain exactly the same data.
func EqualRows(rows1, rows2 []*Row) bool {
	if len(rows1) != len(rows2) {
		return false
	}
	for _, r1 := range rows1 {
		if !ContainsRow(rows2, r1) {
			return false
		}
	}
	return true
}
