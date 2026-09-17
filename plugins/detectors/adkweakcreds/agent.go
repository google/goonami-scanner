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

package adkweakcreds

import (
	"context"
	_ "embed"

	"github.com/google/goonami-scanner/common/clients/llm"
	httptool "github.com/google/goonami-scanner/common/clients/llm/tools/httpclient"
	"github.com/google/goonami-scanner/core/config"
	"github.com/google/goonami-scanner/core/log"
	"google.golang.org/adk/v2/agent"
	"google.golang.org/adk/v2/agent/llmagent"
	"google.golang.org/adk/v2/model/gemini"
	"google.golang.org/adk/v2/tool"
	"google.golang.org/genai"

	nspb "github.com/google/tsunami-security-scanner/proto/go/network_service_go_proto"
)

const (
	llmName      = "authentication-agent"
	llmModelTier = llm.ModelTierFast
)

var (
	//go:embed prompt.md
	llmPrompt string

	// schemaRequestHTTP is the schema for an HTTP request, used by the LLM to return the full answer.
	schemaRequestHTTP = &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"method": &genai.Schema{
				Type: genai.TypeString,
				Enum: []string{"GET", "POST"},
			},
			"path": &genai.Schema{
				Type:        genai.TypeString,
				Description: "The absolute path of the URI to query (e.g., /login). Placeholders like [[username]], [[password]], and [[csrftoken]] MUST be used here if credentials are submitted via query parameters. MUST start with a forward slash.",
			},
			"body": &genai.Schema{
				Type:        genai.TypeString,
				Description: "The raw HTTP body to send in the request (e.g., for POST requests). You MUST use the [[username]], [[password]], and [[csrftoken]] placeholders here to inject the credentials if they are passed in the body (e.g., `username=[[username]]&password=[[password]]`).",
			},
			"extraction_regex": &genai.Schema{
				Type:        genai.TypeString,
				Description: "This field MUST NOT be empty. A robust regular expression containing exactly one capturing group `(...)` to extract the required data or error message (e.g., `(Invalid username or password)` or `name=\"csrf_token\" value=\"([^\"]+)\"`), or a pattern matching an empty or whitespace-only response body (e.g., `^\\s*$` or `^$`) if authentication failure produces an empty response. The extraction_regex must match credential verification errors rather than input schema validation errors. This regex is evaluated ONLY against the raw HTTP response body; do not attempt to match HTTP status codes or headers. Avoid overly broad patterns (e.g., `.*`); the expression must be precise enough to match only the target token or specific failure message.",
				MinLength:   genai.Ptr[int64](1),
			},
			"headers": &genai.Schema{
				Type:        genai.TypeArray,
				Description: "Additional HTTP headers without which the request will fail. If the request requires a 'Content-Type' header value, it has to be specified here.",
				Items: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"name": &genai.Schema{
							Type:        genai.TypeString,
							Description: "The header name.",
						},
						"value": &genai.Schema{
							Type:        genai.TypeString,
							Description: "The header value.",
						},
					},
					Required: []string{"name", "value"},
				},
			},
		},
		Required: []string{"method", "path", "extraction_regex"},
	}

	// authenticationDetailsSchema defines the required fields when auth is supported.
	authenticationDetailsSchema = &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"csrf_request": &genai.Schema{
				Type:        genai.TypeObject,
				Nullable:    genai.Ptr[bool](true),
				Description: "An optional preliminary HTTP request to fetch a CSRF token. ONLY include this if the service strictly requires a dynamic token for login. If a CSRF token is not required by the service, set this field to strictly `null`. Do NOT provide a `csrf_request` object with empty fields (like `\"\"`). The extraction_regex must capture the token.",
				Properties:  schemaRequestHTTP.Properties,
				Required:    schemaRequestHTTP.Required,
			},
			"login_request": &genai.Schema{
				Type:        genai.TypeObject,
				Description: "The primary HTTP request used to submit the credentials. Prefer form-based or dedicated API login requests over HTTP Basic Authentication; only use [[basic_auth]] if no other login mechanism is found. The request MUST NOT be static; it MUST dynamically include the [[password]] placeholder specifically for the secret/password parameter (and optionally [[username]] for the user identifier) in the path or body, or [[basic_auth]] in an Authorization header (`Basic [[basic_auth]]`) for HTTP Basic Authentication. NEVER map [[password]] into a username or user identifier parameter. The extraction_regex must capture the failure message (or `^\\s*$` if authentication failure produces an empty body) to determine authentication failure. For POST requests, the body MUST be provided.",
				Properties:  schemaRequestHTTP.Properties,
				Required:    schemaRequestHTTP.Required,
			},
			"credentials_to_test": &genai.Schema{
				Type:        genai.TypeArray,
				Description: "A list of common, default, or likely username and password pairs to attempt during brute-forcing.",
				MinItems:    genai.Ptr[int64](1),
				MaxItems:    genai.Ptr[int64](10),
				Items: &genai.Schema{
					Type: genai.TypeObject,
					Properties: map[string]*genai.Schema{
						"username": &genai.Schema{Type: genai.TypeString, Description: "A likely username to test (e.g., 'admin', 'root', or derived from context). If the application requires a specific format such as an email address, provide validly formatted usernames (e.g., 'admin@example.com')."},
						"password": &genai.Schema{Type: genai.TypeString, Description: "A likely password to test (e.g., 'password', 'admin', or derived from context)."},
					},
					Required: []string{"password"},
				},
			},
		},
		Required: []string{"login_request", "credentials_to_test"},
	}

	// authenticationSchema is the full answer schema of the LLM.
	authenticationSchema = &genai.Schema{
		Type: genai.TypeObject,
		Properties: map[string]*genai.Schema{
			"supports_authentication": &genai.Schema{
				Type:        genai.TypeBoolean,
				Description: "Set to true ONLY if the application enforces password/secret-based authentication (requires a password, secret token, or API key). Set to false if the application is passwordless (e.g., username-only sign-in, magic links, OTP, SSO redirects) or has no authentication.",
			},
			"authentication_details": &genai.Schema{
				Type:        genai.TypeObject,
				Nullable:    genai.Ptr[bool](true),
				Description: "Required if supports_authentication is true. You MUST omit this field or set this field to strictly `null` if supports_authentication is false. Do not provide an object with empty fields.",
				Properties:  authenticationDetailsSchema.Properties,
				Required:    authenticationDetailsSchema.Required,
			},
		},
		Required: []string{"supports_authentication"},
	}
)

// buildAgent initializes and returns the LLM agent used for authentication strategy discovery.
func buildAgent(ctx context.Context, config *config.Config, service *nspb.NetworkService) (agent.Agent, error) {
	modelName := llm.GetModel(config, llmModelTier)
	model, err := gemini.NewModel(ctx, modelName, &genai.ClientConfig{})
	if err != nil {
		return nil, err
	}

	log.DebugContextf(ctx, log.DebugLevelService, "creating new agent with model %s", modelName)
	serviceTool, err := httptool.New(config, service)
	if err != nil {
		return nil, err
	}

	cfg := llmagent.Config{
		Model:        model,
		Name:         llmName,
		Tools:        []tool.Tool{serviceTool},
		Instruction:  llmPrompt,
		OutputSchema: authenticationSchema,
	}
	ag, err := llmagent.New(cfg)
	if err != nil {
		return nil, err
	}

	return ag, nil
}
