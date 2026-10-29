/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package log

import (
	"context"

	"github.com/google/goonami-scanner/core/net/netendpoint"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

type (
	hostKey    struct{}
	moduleKey  struct{}
	serviceKey struct{}
)

// ContextForHost returns a new context with the host attached.
func ContextForHost(ctx context.Context, host string) context.Context {
	return context.WithValue(ctx, hostKey{}, host)
}

// HostFromContext returns the host attached to the context, or an empty string if none is attached.
func HostFromContext(ctx context.Context) string {
	host, _ := ctx.Value(hostKey{}).(string)
	return host
}

// ContextForModule returns a new context with the module name attached.
func ContextForModule(ctx context.Context, name string) context.Context {
	return context.WithValue(ctx, moduleKey{}, name)
}

// ContextForModuleAndHost returns a new context with both the module name and the host attached.
func ContextForModuleAndHost(ctx context.Context, name string, host string) context.Context {
	return ContextForModule(ContextForHost(ctx, host), name)
}

// ContextForService returns a new context with the service information (host and port) attached.
func ContextForService(ctx context.Context, service *nspb.NetworkService) context.Context {
	if host, err := netendpoint.ToHost(service.GetNetworkEndpoint()); err == nil && host != "" {
		ctx = ContextForHost(ctx, host)
	}
	port := int(service.GetNetworkEndpoint().GetPort().GetPortNumber())
	return context.WithValue(ctx, serviceKey{}, port)
}

// ContextForModuleAndService returns a new context with both the module name and the service
// information (host and port) attached.
func ContextForModuleAndService(ctx context.Context, name string, service *nspb.NetworkService) context.Context {
	return ContextForModule(ContextForService(ctx, service), name)
}
