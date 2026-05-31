package config

import (
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"time"
)

func setValue(oldValue reflect.Value, newValue string, fn func(v reflect.Value) error) error {
	if !oldValue.CanSet() {
		return nil
	}

	k := oldValue.Kind()
	switch k {
	case reflect.Pointer:
		k = oldValue.Type().Elem().Kind()
	case reflect.Struct:
		if oldValue.NumField() == 0 {
			return nil
		}
		return fn(oldValue)
	}

	var err error
	if strings.HasSuffix(oldValue.Type().String(), "time.Duration") {
		d, err := time.ParseDuration(newValue)
		if err != nil {
			return fmt.Errorf("parse duration %q: %w", newValue, err)
		}
		if oldValue.Kind() == reflect.Pointer {
			oldValue.Set(reflect.ValueOf(&d))
		} else {
			oldValue.Set(reflect.ValueOf(d))
		}
		return nil
	} else if oldValue.Type().String() == "*url.URL" {
		return setURLValue(oldValue, newValue)
	} else {
		switch k {
		case reflect.String:
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&newValue))
			} else {
				oldValue.Set(reflect.ValueOf(newValue))
			}
		case reflect.Bool:
			d, err := strconv.ParseBool(newValue)
			if err != nil {
				return fmt.Errorf("parse bool %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Int:
			intSize := 32 << (^uint(0) >> 63)
			i, err := strconv.ParseInt(newValue, 10, intSize)
			d := int(i)
			if err != nil {
				return fmt.Errorf("parse int %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Int8:
			i, err := strconv.ParseInt(newValue, 10, 8)
			d := int8(i)
			if err != nil {
				return fmt.Errorf("parse int8 %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Int16:
			i, err := strconv.ParseInt(newValue, 10, 16)
			d := int16(i)
			if err != nil {
				return fmt.Errorf("parse int16 %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		// NB: int32 is also an alias for a rune
		case reflect.Int32:
			i, err := strconv.ParseInt(newValue, 10, 32)
			d := int32(i)
			if err != nil {
				return fmt.Errorf("parse int32 %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Int64:
			d, err := strconv.ParseInt(newValue, 10, 64)
			if err != nil {
				return fmt.Errorf("parse int64 %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Uint:
			intSize := 32 << (^uint(0) >> 63)
			u, err := strconv.ParseUint(newValue, 10, intSize)
			d := uint(u)
			if err != nil {
				return fmt.Errorf("parse uint %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Uint8:
			u, err := strconv.ParseUint(newValue, 10, 8)
			d := uint8(u)
			if err != nil {
				return fmt.Errorf("parse uint8 %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Uint16:
			u, err := strconv.ParseUint(newValue, 10, 16)
			d := uint16(u)
			if err != nil {
				return fmt.Errorf("parse uint16 %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Uint32:
			u, err := strconv.ParseUint(newValue, 10, 32)
			d := uint32(u)
			if err != nil {
				return fmt.Errorf("parse uint32 %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Uint64:
			d, err := strconv.ParseUint(newValue, 10, 64)
			if err != nil {
				return fmt.Errorf("parse uint64 %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Float32:
			f, err := strconv.ParseFloat(newValue, 32)
			d := float32(f)
			if err != nil {
				return fmt.Errorf("parse float32 %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Float64:
			d, err := strconv.ParseFloat(newValue, 64)
			if err != nil {
				return fmt.Errorf("parse float64 %q: %w", newValue, err)
			}
			if oldValue.Kind() == reflect.Pointer {
				oldValue.Set(reflect.ValueOf(&d))
			} else {
				oldValue.Set(reflect.ValueOf(d))
			}
		case reflect.Slice:
			switch oldValue.Type().Elem().Kind() {
			// a []uint8 is a an alias for a []byte
			case reflect.Uint8:
				d := []byte(newValue)
				if oldValue.Kind() == reflect.Pointer {
					oldValue.Set(reflect.ValueOf(&d))
				} else {
					oldValue.Set(reflect.ValueOf(d))
				}
			case reflect.Pointer:
				for i := 0; i < oldValue.Len(); i++ {
					if ferr := fn(oldValue.Index(i)); ferr != nil {
						return ferr
					}
				}
			default:
				return ErrorUnsupportedType{oldValue.Type()}
			}
		default:
			return ErrorUnsupportedType{oldValue.Type()}
		}
	}
	return err
}

// setURLValue parses raw as a URL and assigns it to v. If v already holds a
// non-nil URL (parsed from config), the default is not applied.
func setURLValue(v reflect.Value, raw string) error {
	if !v.IsNil() {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("parse url %q: %w", raw, err)
	}
	if raw != "" {
		v.Set(reflect.ValueOf(u))
	}
	return nil
}
