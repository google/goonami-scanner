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

// Package module provides the different interfaces for modules used in Goonami.
package module

// Module is the interface that every Goonami module will indirectly implement.
type Module interface {
	// Name of the module.
	Name() string
}

// BaseModule is the base implementation of the Module interface. It should be used by all modules.
type BaseModule struct {
	name string
}

// NewBaseModule creates a new BaseModule.
func NewBaseModule(name string) *BaseModule {
	return &BaseModule{
		name: name,
	}
}

// Name returns the name of the module.
func (m *BaseModule) Name() string {
	return m.name
}
