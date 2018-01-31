// Copyright 2018, OpenCensus Authors
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

// Package propagation contains HTTP propagators.
package propagation

import (
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"

	"go.opencensus.io/trace"
)

const (
	supportedVersion = 0
	header           = "TraceContext"
)

// HTTPFormat implements the TraceContext trace propagation format.
// See https://github.com/w3c/distributed-tracing for more information.
type HTTPFormat struct{}

// FromRequest extracts a TraceContext span context from incoming requests.
func (f *HTTPFormat) FromRequest(req *http.Request) (sc trace.SpanContext, ok bool) {
	h := req.Header.Get(header)
	if h == "" {
		return trace.SpanContext{}, false
	}
	sections := strings.Split(h, "-")
	if len(sections) < 3 {
		return trace.SpanContext{}, false
	}

	ver, err := hex.DecodeString(sections[0])
	if err != nil {
		return trace.SpanContext{}, false
	}
	if len(ver) == 0 || int(ver[0]) > supportedVersion {
		return trace.SpanContext{}, false
	}

	tid, err := hex.DecodeString(sections[1])
	if err != nil {
		return trace.SpanContext{}, false
	}
	copy(sc.TraceID[:], tid)

	sid, err := hex.DecodeString(sections[2])
	if err != nil {
		return trace.SpanContext{}, false
	}
	copy(sc.SpanID[:], sid)

	if len(sections) == 4 {
		opts, err := hex.DecodeString(sections[3])
		if err != nil || len(opts) < 1 {
			return trace.SpanContext{}, false
		}
		sc.TraceOptions = trace.TraceOptions(opts[0])
	}

	return sc, true
}

// ToRequest modifies the given request to include a TraceContext header.
func (f *HTTPFormat) ToRequest(sc trace.SpanContext, req *http.Request) {
	h := fmt.Sprintf("%s-%s-%s-%s",
		hex.EncodeToString([]byte{supportedVersion}),
		hex.EncodeToString(sc.TraceID[:]),
		hex.EncodeToString(sc.SpanID[:]),
		hex.EncodeToString([]byte{byte(sc.TraceOptions)}))
	req.Header.Set(header, h)
}
