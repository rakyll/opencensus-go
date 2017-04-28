// Copyright 2017 Google Inc.
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

// Package topb defines the helpers methods to convert pure Go objects to
// protobuf descriptors to representing them.
package topb

import (
	"fmt"
	"time"

	"github.com/golang/glog"
	istats "github.com/google/instrumentation-go/stats"
	pb "github.com/google/instrumentation-proto/stats"
)

// View converts the pure Go struct to a protocol buffer View object defined in
// github.com/google/instrumentation-go/stats.View
func View(vw *istats.View) (*pb.View, error) {
	vwPb := &pb.View{
		ViewName: vw.ViewDesc.ViewDescCommon().Name,
	}
	switch t := vw.ViewAgg.(type) {
	case *istats.DistributionView:
		vwPb.View = distributionViewPb(t)
	case *istats.IntervalView:
		vwPb.View = intervalViewPb(t)
	case *istats.GaugeBoolView:
	case *istats.GaugeFloat64View:
	case *istats.GaugeInt64View:
	case *istats.GaugeStringView:
	case *istats.CounterInt64View:
	default:
		return nil, fmt.Errorf("%T no supported in topb.View()", t)
	}
	return vwPb, nil
}

func distributionViewPb(vw *istats.DistributionView) *pb.View_DistributionView {
	var aggs []*pb.DistributionAggregation
	for _, a := range vw.Aggregations {
		agg := &pb.DistributionAggregation{
			Count: a.Count,
			Mean:  a.Mean,
			Range: &pb.DistributionAggregation_Range{
				Max: a.Max,
				Min: a.Min,
			},
			Sum:          a.Sum,
			BucketCounts: a.CountPerBucket,
		}
		for _, t := range a.Tags {
			v, ok := t.Value().(string)
			if !ok {
				glog.Infof("%v is of type %T. Expecting type string", t.Value(), t.Value())
			}
			agg.Tags = append(agg.Tags, &pb.Tag{
				Key:   t.Key().Name(),
				Value: v,
			})
		}
		aggs = append(aggs, agg)
	}

	return &pb.View_DistributionView{
		DistributionView: &pb.DistributionView{
			Start: &pb.Timestamp{
				Seconds: vw.Start.Unix(),
				Nanos:   int32(vw.Start.Nanosecond()),
			},
			End: &pb.Timestamp{
				Seconds: vw.End.Unix(),
				Nanos:   int32(vw.End.Nanosecond()),
			},
			Aggregations: aggs,
		},
	}
}

func intervalViewPb(vw *istats.IntervalView) *pb.View_IntervalView {
	var aggs []*pb.IntervalAggregation
	for _, a := range vw.Aggregations {
		agg := &pb.IntervalAggregation{}
		for _, t := range a.Tags {
			v, ok := t.Value().(string)
			if !ok {
				glog.Infof("%v is of type %T. Expecting type string", t.Value(), t.Value())
			}
			agg.Tags = append(agg.Tags, &pb.Tag{
				Key:   t.Key().Name(),
				Value: v,
			})
		}

		for _, ais := range a.IntervalStats {
			sec := int64(ais.Duration.Seconds())
			nanos := int32((ais.Duration - (time.Duration(sec) * time.Second)).Nanoseconds())
			i := &pb.IntervalAggregation_Interval{
				Count: ais.Count,
				Sum:   ais.Sum,
				IntervalSize: &pb.Duration{
					Seconds: sec,
					Nanos:   nanos,
				},
			}
			agg.Intervals = append(agg.Intervals, i)
		}
		aggs = append(aggs, agg)
	}

	return &pb.View_IntervalView{
		IntervalView: &pb.IntervalView{
			Aggregations: aggs,
		},
	}
}

// func gaugeBoolViewPb(vw *istats.GaugeBoolView) *pb.View_GaugeBoolView {
// 	return &pb.GaugeBoolView{}
// }

// func gaugeFloat64ViewPb(vw *istats.GaugeFloat64View) *pb.View_GaugeFloat64View {
// 	return &pb.GaugeFloat64View{}
// }

// func gaugeInt64ViewPb(vw *istats.GaugeInt64View) *pb.View_GaugeInt64View {
// 	return &pb.GaugeInt64View{}
// }

// func gaugeStringViewPb(vw *istats.GaugeStringView) *pb.View_GaugeStringView {
// 	return &pb.GaugeStringView{}
// }

//func counterInt64ViewPb(vw istats.CounterInt64View) *pb.View_CounterInt64View {
//  return &pb.CounterInt64View{}
//}