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

package environment

const (
	// VarUtilTimestamp is the timestamp of the start of the workflow execution in milliseconds.
	VarUtilTimestamp = "T_UTL_CURRENT_TIMESTAMP_MS"

	// VarNetServiceBaseURL is the base URL of the network service.
	VarNetServiceBaseURL = "T_NS_BASEURL"

	// VarNetServiceProtocol is the protocol (tcp, udp) of the network service.
	VarNetServiceProtocol = "T_NS_PROTOCOL"

	// VarNetServiceHostname is the hostname of the network service.
	VarNetServiceHostname = "T_NS_HOSTNAME"

	// VarNetServicePort is the port of the network service.
	VarNetServicePort = "T_NS_PORT"

	// VarNetServiceIP is the IP address of the network service.
	VarNetServiceIP = "T_NS_IP"

	// VarCallbackURI is the full URI of the callback server. It is used to record an interaction.
	VarCallbackURI = "T_CBS_URI"

	// VarCallbackSecret is the secret of the callback server. It is generated per service and per
	// workflow run.
	VarCallbackSecret = "T_CBS_SECRET"

	// VarCallbackAddress is the address of the callback server.
	VarCallbackAddress = "T_CBS_ADDRESS"

	// VarCallbackPort is the port of the callback server.
	VarCallbackPort = "T_CBS_PORT"

	// VarTestingMagicPrefix is the prefix for all magic strings.
	VarTestingMagicPrefix = "TSUNAMI_MAGIC_"

	// VarTestingMagicAnyURI (Testing) is a magic string that can be used in place of any URI.
	VarTestingMagicAnyURI = "TSUNAMI_MAGIC_ANY_URI"

	// VarTestingMagicEchoServer (Testing) is a magic that forces the engine to repeat the request as
	// the HTTP response.
	VarTestingMagicEchoServer = "TSUNAMI_MAGIC_ECHO_SERVER"
)
