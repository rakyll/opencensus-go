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

package stats

import (
	"fmt"
	"reflect"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/golang/glog"
	"github.com/google/instrumentation-go/stats/tagging"
	"golang.org/x/net/context"
)

type record struct {
	t    time.Time
	muts []tagging.Mutation
	v    float64
}

type view struct {
	viewDesc     ViewDesc
	wantViewAgg  *DistributionView
	registerTime time.Time
	retrieveTime time.Time
}

type ucTestData struct {
	measureDesc MeasureDesc
	views       []*view
	records     []record
}

func (td *ucTestData) String() string {
	if td == nil {
		return "nil"
	}
	return fmt.Sprintf("%v", td.measureDesc)
}

func registerKeys(count int) []tagging.KeyStringUTF8 {
	mgr := tagging.DefaultKeyManager()
	var keys []tagging.KeyStringUTF8

	for i := 0; i < count; i++ {
		k1, err := mgr.CreateKeyStringUTF8("keyIdentifier" + strconv.Itoa(i))
		if err != nil {
			glog.Fatalf("RegisterKeys(_) failed. %v\n", err)
		}
		keys = append(keys, k1)
	}
	return keys
}

func createMutations(keys []tagging.KeyStringUTF8) []tagging.Mutation {
	var mutations []tagging.Mutation
	for i, k := range keys {
		mutations = append(mutations, k.CreateMutation("valueIdentifier"+strconv.Itoa(i), tagging.BehaviorAddOrReplace))
	}
	return mutations
}

func registerMeasure(uc *usageCollector, n string) *measureDescFloat64 {
	mu := &MeasurementUnit{
		Power10: 6,
		Numerators: []BasicUnit{
			BytesUnit,
		},
	}
	mf64 := NewMeasureDescFloat64(n, "", mu)
	if err := uc.registerMeasureDesc(mf64); err != nil {
		glog.Fatalf("RegisterMeasure(_) failed. %v\n", err)
	}
	return mf64
}

func registerView(uc *usageCollector, n string, measureName string, keys []tagging.KeyStringUTF8) *DistributionViewDesc {
	vw := &DistributionViewDesc{
		Vdc: &ViewDescCommon{
			Name:            n,
			Description:     "",
			MeasureDescName: measureName,
		},
		Bounds: []float64{0, 10, 20, 30, 40, 50, 60, 70, 80, 90, 100},
	}
	for _, k := range keys {
		vw.Vdc.TagKeys = append(vw.Vdc.TagKeys, k)
	}
	if err := uc.registerViewDesc(vw, time.Now()); err != nil {
		glog.Fatalf("RegisterView(_) failed. %v\n", err)
	}
	return vw
}

func Test_UsageCollector_CreateKeys_RegisterMeasure_RegisterView_Records_RetrieveView(t *testing.T) {
	registerTime := time.Now()
	retrieveTime := registerTime.Add(10 * time.Second)

	k1, err := tagging.DefaultKeyManager().CreateKeyStringUTF8("k1")
	if err != nil {
		t.Fatalf("creating keyString failed. %v ", err)
	}
	k2, err := tagging.DefaultKeyManager().CreateKeyStringUTF8("k2")
	if err != nil {
		t.Fatalf("creating keyString failed. %v ", err)
	}
	uctds := []*ucTestData{
		{
			&measureDescFloat64{
				&measureDesc{
					name: "measure1",
					unit: &MeasurementUnit{1, []BasicUnit{BytesUnit}, []BasicUnit{}},
				},
			},
			[]*view{
				{
					viewDesc: &DistributionViewDesc{
						Vdc: &ViewDescCommon{
							Name:            "view1",
							MeasureDescName: "measure1",
							TagKeys:         []tagging.Key{k1, k2},
						},
						Bounds: []float64{15},
					},
					registerTime: registerTime,
					retrieveTime: retrieveTime,
					wantViewAgg: &DistributionView{
						Aggregations: []*DistributionAgg{
							{
								&DistributionStats{
									3,
									10,
									20,
									30,
									60,
									[]int64{1, 2},
								},
								[]tagging.Tag{k1.CreateTag("v1"), k2.CreateTag("v2")},
							},
							{
								&DistributionStats{
									3,
									10,
									20,
									30,
									60,
									[]int64{1, 2},
								},
								[]tagging.Tag{k1.CreateTag("v1")},
							},
						},
						Start: registerTime,
						End:   retrieveTime,
					},
				},
			},
			[]record{
				{
					registerTime.Add(1 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
					},
					10,
				},
				{
					registerTime.Add(2 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
					},
					20,
				},
				{
					registerTime.Add(3 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
					},
					30,
				},
				{
					registerTime.Add(4 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
						k2.CreateMutation("v2", tagging.BehaviorAddOrReplace),
					},
					10,
				},
				{
					registerTime.Add(5 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
						k2.CreateMutation("v2", tagging.BehaviorAddOrReplace),
					},
					20,
				},
				{
					registerTime.Add(6 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
						k2.CreateMutation("v2", tagging.BehaviorAddOrReplace),
					},
					30,
				},
			},
		},
		{
			&measureDescFloat64{
				&measureDesc{
					name: "measure2",
					unit: &MeasurementUnit{2, []BasicUnit{BytesUnit}, []BasicUnit{}},
				},
			},
			[]*view{
				{
					viewDesc: &DistributionViewDesc{
						Vdc: &ViewDescCommon{
							Name:            "allTagsView",
							MeasureDescName: "measure2",
							TagKeys:         []tagging.Key{},
						},
						Bounds: []float64{25},
					},
					registerTime: registerTime,
					retrieveTime: retrieveTime,
					wantViewAgg: &DistributionView{
						Aggregations: []*DistributionAgg{
							{
								&DistributionStats{
									6,
									10,
									20,
									30,
									120,
									[]int64{4, 2},
								},
								[]tagging.Tag(nil),
							},
						},
						Start: registerTime,
						End:   retrieveTime,
					},
				},
				{
					viewDesc: &DistributionViewDesc{
						Vdc: &ViewDescCommon{
							Name:            "view1",
							MeasureDescName: "measure2",
							TagKeys:         []tagging.Key{k1, k2},
						},
						Bounds: []float64{15},
					},
					registerTime: registerTime,
					retrieveTime: retrieveTime,
					wantViewAgg: &DistributionView{
						Aggregations: []*DistributionAgg{
							{
								&DistributionStats{
									3,
									10,
									20,
									30,
									60,
									[]int64{1, 2},
								},
								[]tagging.Tag{k1.CreateTag("v1"), k2.CreateTag("v2")},
							},
							{
								&DistributionStats{
									3,
									10,
									20,
									30,
									60,
									[]int64{1, 2},
								},
								[]tagging.Tag{k1.CreateTag("v1")},
							},
						},
						Start: registerTime,
						End:   retrieveTime,
					},
				},
				{
					viewDesc: &DistributionViewDesc{
						Vdc: &ViewDescCommon{
							Name:            "view2",
							MeasureDescName: "measure2",
							TagKeys:         []tagging.Key{k1, k2},
						},
						Bounds: []float64{25},
					},
					registerTime: registerTime,
					retrieveTime: retrieveTime,
					wantViewAgg: &DistributionView{
						Aggregations: []*DistributionAgg{
							{
								&DistributionStats{
									3,
									10,
									20,
									30,
									60,
									[]int64{2, 1},
								},
								[]tagging.Tag{k1.CreateTag("v1"), k2.CreateTag("v2")},
							},
							{
								&DistributionStats{
									3,
									10,
									20,
									30,
									60,
									[]int64{2, 1},
								},
								[]tagging.Tag{k1.CreateTag("v1")},
							},
						},
						Start: registerTime,
						End:   retrieveTime,
					},
				},
				{
					viewDesc: &DistributionViewDesc{
						Vdc: &ViewDescCommon{
							Name:            "view3",
							MeasureDescName: "measure2",
							TagKeys:         []tagging.Key{k1},
						},
						Bounds: []float64{25},
					},
					registerTime: registerTime,
					retrieveTime: retrieveTime,
					wantViewAgg: &DistributionView{
						Aggregations: []*DistributionAgg{
							{
								&DistributionStats{
									6,
									10,
									20,
									30,
									120,
									[]int64{4, 2},
								},
								[]tagging.Tag{k1.CreateTag("v1")},
							},
						},
						Start: registerTime,
						End:   retrieveTime,
					},
				},
			},
			[]record{
				{
					registerTime.Add(1 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
					},
					10,
				},
				{
					registerTime.Add(2 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
					},
					20,
				},
				{
					registerTime.Add(3 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
					},
					30,
				},
				{
					registerTime.Add(4 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
						k2.CreateMutation("v2", tagging.BehaviorAddOrReplace),
					},
					10,
				},
				{
					registerTime.Add(5 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
						k2.CreateMutation("v2", tagging.BehaviorAddOrReplace),
					},
					20,
				},
				{
					registerTime.Add(6 * time.Second),
					[]tagging.Mutation{
						k1.CreateMutation("v1", tagging.BehaviorAddOrReplace),
						k2.CreateMutation("v2", tagging.BehaviorAddOrReplace),
					},
					30,
				},
			},
		},
	}

	for _, td := range uctds {
		uc := &usageCollector{
			mDescriptors: make(map[string]MeasureDesc),
			vDescriptors: make(map[string]ViewDesc),
		}
		td.measureDesc.Meta().aggViewDescs = make(map[ViewDesc]struct{})
		uc.registerMeasureDesc(td.measureDesc)
		for _, vw := range td.views {
			uc.registerViewDesc(vw.viewDesc, vw.registerTime)
		}

		for _, r := range td.records {
			m := &measurementFloat64{
				md: td.measureDesc,
				v:  r.v,
			}
			ctx := tagging.ContextWithDerivedTagsSet(context.Background(), r.muts...)
			ts := tagging.FromContext(ctx)
			uc.recordMeasurement(r.t, ts, m)
		}

		for _, vw := range td.views {
			gotVw, err := uc.retrieveViewByName(vw.viewDesc.ViewDescCommon().Name, vw.retrieveTime)
			if err != nil {
				t.Errorf("got error %v (test case: %v), want no error", err, td)
			}

			switch gotVwAgg := gotVw.ViewAgg.(type) {
			case *DistributionView:
				if len(gotVwAgg.Aggregations) != len(vw.wantViewAgg.Aggregations) {
					t.Errorf("got %v aggregations (test case: %v, view:%v), want %v aggregations", len(gotVwAgg.Aggregations), td, vw.viewDesc.ViewDescCommon().Name, len(vw.wantViewAgg.Aggregations))
					continue
				}

				for _, gotAgg := range gotVwAgg.Aggregations {
					found := false
					for _, wantAgg := range vw.wantViewAgg.Aggregations {
						if reflect.DeepEqual(gotAgg, wantAgg) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("got unexpected aggregation %v (test case: %v)", gotAgg, td)
					}
				}
			default:
				t.Errorf("got view aggregation type %v (test case: %v), want %T", gotVwAgg, td, vw.wantViewAgg)
			}

		}
	}
}

func Test_UsageCollector_10Keys_1Measure_1View_10Records(t *testing.T) {
	keys := registerKeys(10)
	mutations := createMutations(keys)

	uc := newUsageCollector()
	m := registerMeasure(uc, "m")
	_ = registerView(uc, "v", "m", keys)

	ctx := tagging.ContextWithDerivedTagsSet(context.Background(), mutations...)
	ts := tagging.FromContext(ctx)

	for j := 0; j < 10; j++ {
		measurement := m.CreateMeasurement(float64(j))
		uc.recordMeasurement(time.Now(), ts, measurement)
	}
	retrieved := uc.retrieveViewsAdhoc(nil, nil, time.Now())

	if len(retrieved) != 1 {
		t.Fatalf("got %v views retrieved, want 1 view", len(retrieved))
	}

	dv, ok := retrieved[0].ViewAgg.(*DistributionView)
	if !ok {
		t.Errorf("got retrieved view of type %T, want view of type *DistributionView", dv)
	}

	if len(dv.Aggregations) != 1 {
		t.Errorf("got %v unique aggregations, want 1 single aggregation", len(dv.Aggregations))
	}

	for _, agg := range dv.Aggregations {
		if agg.DistributionStats.Count != 10 {
			t.Errorf("got %v records for aggregation %v, want 10 records", agg.DistributionStats.Count, agg)
		}
	}
}

func Benchmark_Record_1Measurement_With_1Tags_To_1View(b *testing.B) {
	keys := registerKeys(1)
	mutations := createMutations(keys)
	uc := newUsageCollector()
	m := registerMeasure(uc, "m")

	ctx := tagging.ContextWithDerivedTagsSet(context.Background(), mutations...)
	ts := tagging.FromContext(ctx)

	_ = registerView(uc, "v1", "m", keys)

	measurement := m.CreateMeasurement(float64(1))
	for i := 0; i < b.N; i++ {
		uc.recordMeasurement(time.Now(), ts, measurement)
	}
}

func Benchmark_Record_1Measurement_With_10Tags_To_10Views(b *testing.B) {
	keys := registerKeys(10)
	mutations := createMutations(keys)
	uc := newUsageCollector()
	m := registerMeasure(uc, "m")

	ctx := tagging.ContextWithDerivedTagsSet(context.Background(), mutations...)
	ts := tagging.FromContext(ctx)

	for i := 0; i < 10; i++ {
		_ = registerView(uc, "v"+strconv.Itoa(i), "m", keys)
	}

	measurement := m.CreateMeasurement(float64(1))
	for i := 0; i < b.N; i++ {
		uc.recordMeasurement(time.Now(), ts, measurement)
	}
}

func TestUnsafe(t *testing.T) {
	sss := ""
	ss := "a"
	ls := "abcdefghijklmnopqrst"
	f := 100.55
	i := int64(100)
	b := true

	dataSSS := []byte(sss)

	dataSS := []byte(ss)

	dataLS := []byte(ls)

	dataF := make([]byte, 8)
	*(*float64)(unsafe.Pointer(&dataF[0])) = f

	dataI := make([]byte, 8)
	*(*int64)(unsafe.Pointer(&dataI[0])) = i

	dataB := make([]byte, 1)
	*(*bool)(unsafe.Pointer(&dataB[0])) = b

	fmt.Printf("SSS: %v\n", string(dataSSS))
	fmt.Printf("SS: %v\n", string(dataSS))
	fmt.Printf("LS: %v\n", string(dataLS))
	fmt.Printf("F: %v\n", *(*float64)(unsafe.Pointer(&dataF[0])))
	fmt.Printf("I: %v\n", *(*int64)(unsafe.Pointer(&dataI[0])))
	fmt.Printf("B: %v\n", *(*int64)(unsafe.Pointer(&dataB[0])))
}