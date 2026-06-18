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

package config

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/goonami-scanner/core/log"
	"google.golang.org/protobuf/reflect/protoreflect"
)

var aliases = map[string]string{
	"ports":       "globalcfg.ports_to_scan",
	"http_client": "globalcfg.http_client",
}

// ApplyOverrides applies a list of overrides to the configuration.
// The format for overrides is "key=value".
func (c *Config) ApplyOverrides(ctx context.Context, overrides []string) error {
	ctx = log.ContextForModule(ctx, "core/config")
	for _, override := range overrides {
		if err := c.applyOverride(ctx, override); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) applyOverride(ctx context.Context, override string) error {
	parts := strings.SplitN(override, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("%w %q, expected key=value", ErrInvalidOverrideFormat, override)
	}

	key, value := parts[0], parts[1]

	// Resolve alias
	if aliased, ok := aliases[key]; ok {
		key = aliased
	}

	log.InfoContextf(ctx, "overriding configuration %q with value %q", key, value)
	return setField(c.proto.ProtoReflect(), key, value)
}

func setField(m protoreflect.Message, key string, value string) error {
	parts := strings.SplitN(key, ".", 2)
	name := protoreflect.Name(parts[0])
	fd := m.Descriptor().Fields().ByName(name)
	if fd == nil {
		return fmt.Errorf("%w: field %q not found in %q", ErrFieldNotFound, name, m.Descriptor().FullName())
	}

	if len(parts) == 1 {
		return processLeaf(m, fd, value)
	}

	nextMsg, err := processMiddleNode(m, fd)
	if err != nil {
		return err
	}

	return setField(nextMsg, parts[1], value)
}

// processMiddleNode handles intermediate nodes in the field path, ensuring the message exists.
func processMiddleNode(m protoreflect.Message, fd protoreflect.FieldDescriptor) (protoreflect.Message, error) {
	if fd.Kind() != protoreflect.MessageKind {
		return nil, fmt.Errorf("%w: field %q is not a message", ErrFieldNotMessage, fd.Name())
	}

	if !m.Has(fd) {
		m.Set(fd, m.NewField(fd))
	}

	return m.Mutable(fd).Message(), nil
}

// processLeaf handles the final field in the path, parsing and setting the value.
func processLeaf(m protoreflect.Message, fd protoreflect.FieldDescriptor, value string) error {
	// If the field is a list, we truncate its content.
	if fd.IsList() {
		list := m.Mutable(fd).List()
		for list.Len() > 0 {
			list.Truncate(0)
		}

		vals := strings.Split(value, ",")
		for _, v := range vals {
			pv, err := parseValue(fd, v)
			if err != nil {
				return err
			}
			list.Append(pv)
		}
		return nil
	}

	pv, err := parseValue(fd, value)
	if err != nil {
		return err
	}

	m.Set(fd, pv)
	return nil
}

func parseValue(fd protoreflect.FieldDescriptor, value string) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(value), nil
	case protoreflect.BoolKind:
		b, err := strconv.ParseBool(value)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("%w: %v", ErrConfigUnmarshal, err)
		}
		return protoreflect.ValueOfBool(b), nil
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		i, err := strconv.ParseInt(value, 10, 32)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("%w: %v", ErrConfigUnmarshal, err)
		}
		return protoreflect.ValueOfInt32(int32(i)), nil
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		i, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("%w: %v", ErrConfigUnmarshal, err)
		}
		return protoreflect.ValueOfInt64(i), nil
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		i, err := strconv.ParseUint(value, 10, 32)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("%w: %v", ErrConfigUnmarshal, err)
		}
		return protoreflect.ValueOfUint32(uint32(i)), nil
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		i, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("%w: %v", ErrConfigUnmarshal, err)
		}
		return protoreflect.ValueOfUint64(i), nil
	default:
		return protoreflect.Value{}, fmt.Errorf("%w: unsupported field kind %v for field %q", ErrUnsupportedFieldKind, fd.Kind(), fd.Name())
	}
}
