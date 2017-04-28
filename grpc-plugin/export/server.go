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

// Package export defines the GRPC server implementing the GRPC server
// "github.com/grpc/grpc-proto/grpc/instrumentation/v1alpha". This is a sample
// endpoint to report/export collected statistics and tracing information for
// both the default GRPC metrics and any other ad hoc collected metric.
package export

import (
	"fmt"

	"github.com/golang/glog"
	pb "github.com/golang/protobuf/ptypes/empty"
	"github.com/google/instrumentation-go/grpc-plugin/topb"
	istats "github.com/google/instrumentation-go/stats"
	statsPb "github.com/google/instrumentation-proto/stats"
	spb "github.com/grpc/grpc-proto/grpc/instrumentation/v1alpha"
	"golang.org/x/net/context"
)

type server struct {
	c chan *istats.View
}

// NewServer returns a new instance of the server implementing the GRPC server
// "github.com/grpc/grpc-proto/grpc/instrumentation/v1alpha".
func NewServer() spb.MonitoringServer {
	s := &server{
		c: make(chan *istats.View, 1024),
	}
	return s
}

// GetCanonicalRpcStats returns the canonical/default RPC stats for GRPC.
func (s *server) GetCanonicalRpcStats(ctx context.Context, empty *pb.Empty) (*spb.CanonicalRpcStats, error) {
	/*
			RpcClientErrors
			RpcClientRequestBytes
			RpcClientResponseBytes
			RpcClientElapsedTime (RoundTripLatency)
			RpcClientServerElapsedTime

		// UncompressedRequestBytes defined in java but not in proto
		// UncompressedResponseBytes defined in java but not in proto
			RpcClientCompletedRpcs
			RpcClientStartedRpcs
			RpcClientRequestCount
			RpcClientResponseCount

			RpcServerErrors
			RpcServerRequestBytes
			RpcServerResponseBytes
			RpcServerElapsedTime	   // What is the difference between serverElapsedTime and ServerServerElapsedTime ?
			RpcServerServerElapsedTime // What is the difference between serverElapsedTime and ServerServerElapsedTime ?
			RpcServerCompletedRpcs
			RpcServerRequestCount	   // This is the started count.
		// UncompressedRequestBytes defined in java but not in proto
		// UncompressedResponseBytes defined in java but not in proto
			RpcServerResponseCount     // Why is this needed.
	*/
	return nil, nil
}

// GetStats allows to query for any specific stat or set of stats,
func (s *server) GetStats(ctx context.Context, req *spb.StatsRequest) (*spb.StatsResponse, error) {
	views := istats.RetrieveViews(req.ViewNames, req.MeasurementNames)

	resp, err := buildStatsResponse(views)
	if err != nil {
		return nil, err
	}

	if req.DontIncludeDescriptorsInFirstResponse {
		return resp, nil
	}

	// TODO(mmoakil): where does req.DontIncludeDescriptorsInFirstResponse need
	// to be included? Only CanonicalRpcStats have these. And interestingly
	// GetCanonicalRpcStats(...) doesn't have a
	// DontIncludeDescriptorsInFirstResponse.
	return resp, nil
}

// WatchStats requests the server to stream back snapshots of the requested stats.
func (s *server) WatchStats(req *spb.StatsRequest, stream spb.Monitoring_WatchStatsServer) error {
	subscription := &istats.MultiSubscription{
		ViewNames:    req.GetViewNames(),
		MeasureNames: req.GetMeasurementNames(),
		C:            make(chan []*istats.View, 1024),
	}
	defer istats.Unsubscribe(subscription)

	err := istats.Subscribe(subscription)
	if err != nil {
		return fmt.Errorf("WatchStats(_) failed to subscribe. %v", err)
	}
	if glog.V(3) {
		glog.Infof("export.server.WatchStats(_) subscribed to (views, measures) = (%v,%v)", subscription.ViewNames, subscription.MeasureNames)
	}
	for {
		views := <-subscription.C
		if glog.V(3) {
			glog.Infof("export.server.WatchStats(_) %v views retrieved", len(views))
		}

		resp, err := buildStatsResponse(views)
		if err != nil {
			return err
		}
		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// GetRequestTraces returns collected traces.
func (s *server) GetRequestTraces(ctx context.Context, req *spb.TraceRequest) (*spb.TraceResponse, error) {
	return nil, nil
}

// GetCustomMonitoringData return application-defined groups of monitoring
// data. This is a low level facility to allow extension of the monitoring API
// to application-specific monitoring data. Frameworks may use this to define
// additional groups of monitoring data made available by servers.
func (s *server) GetCustomMonitoringData(ctx context.Context, req *spb.MonitoringDataGroup) (*spb.CustomMonitoringData, error) {
	return nil, nil
}

func buildStatsResponse(vws []*istats.View) (*spb.StatsResponse, error) {
	resp := &spb.StatsResponse{}

	for _, vw := range vws {
		vwpb, err := topb.View(vw)
		if err != nil {
			return nil, err
		}

		resp.ViewResponses = append(resp.ViewResponses, &spb.ViewResponse{
			MeasurementDescriptor: &statsPb.MeasurementDescriptor{},
			ViewDescriptor:        &statsPb.ViewDescriptor{},
			View:                  vwpb,
		})
	}

	return resp, nil
}