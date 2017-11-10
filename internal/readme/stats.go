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

package readme

import (
	"context"
	"log"
	"time"

	"go.opencensus.io/stats"
)

// README.md is generated with the examples here by using embedmd.
// For more details, see https://github.com/rakyll/embedmd.

func statsExamples() {
	ctx := context.Background()

	// START measure
	videoSize, err := stats.NewMeasureInt64("my.org/video_size", "processed video size", "MB")
	if err != nil {
		log.Fatal(err)
	}
	// END measure
	_ = videoSize

	// START findMeasure
	m, err := stats.FindMeasure("my.org/video_size")
	if err != nil {
		log.Fatal(err)
	}
	// END findMeasure

	_ = m

	// START deleteMeasure
	if err := stats.DeleteMeasure(m); err != nil {
		log.Fatal(err)
	}
	// END deleteMeasure

	// START aggs
	distAgg := stats.DistributionAggregation([]float64{0, 1 << 32, 2 << 32, 3 << 32})
	countAgg := stats.CountAggregation{}
	// END aggs

	_, _ = distAgg, countAgg

	// START windows
	slidingTimeWindow := stats.SlidingTimeWindow{
		Duration:  10 * time.Second,
		Intervals: 5,
	}

	slidingCountWindow := stats.SlidingCountWindow{
		Count:   100,
		Subsets: 10,
	}

	cumWindow := stats.CumulativeWindow{}
	// END windows

	_, _, _ = slidingTimeWindow, slidingCountWindow, cumWindow

	// START view
	view := stats.NewView(
		"my.org/video_size_distribution",
		"distribution of processed video size over time",
		nil,
		videoSize,
		distAgg,
		cumWindow,
	)
	if err := stats.RegisterView(view); err != nil {
		log.Fatal(err)
	}
	// END view

	// START findView
	v, err := stats.FindView("my.org/video_size_distribution")
	if err != nil {
		log.Fatal(err)
	}
	// END findView

	_ = v

	// START unregisterView
	if v.Unregister(); err != nil {
		log.Fatal(err)
	}
	// END unregisterView

	// START reportingPeriod
	stats.SetReportingPeriod(5 * time.Second)
	// END reportingPeriod

	// START record
	stats.Record(ctx, videoSize.M(102478))
	// END record

	// START subscribe
	if view.Subscribe(); err != nil {
		log.Fatal(err)
	}
	// END subscribe

	// START registerExporter
	// Register an exporter to be able to retrieve
	// the data from the subscribed views.
	stats.RegisterExporter(&exporter{})
	// END registerExporter
}

// START exporter

type exporter struct{}

func (e *exporter) Export(vd *stats.ViewData) {
	log.Println(vd)
}

// END exporter
