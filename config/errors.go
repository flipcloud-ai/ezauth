package config

import (
	"fmt"
	"reflect"
)

// ErrNotAStructPointer indicates that we were expecting a pointer to a struct,
// but got something else.
type ErrNotAStructPointer string

func newErrNotAStructPointer(v interface{}) ErrNotAStructPointer {
	return ErrNotAStructPointer(fmt.Sprintf("%T", v))
}

// Error implements the error interface.
func (e ErrNotAStructPointer) Error() string {
	return fmt.Sprintf("expected a struct, instead got a %s", string(e))
}

// ErrorUnsettable is used when a field cannot be set.
type ErrorUnsettable string

func newErrorUnsettable(v interface{}) ErrorUnsettable {
	return ErrorUnsettable(fmt.Sprintf("%s", v))
}

// Error implements the error interface.
func (e ErrorUnsettable) Error() string {
	return fmt.Sprintf("can't set field %s", string(e))
}

// ErrorUnsupportedType indicates that the type of the struct field is not yet
// support in this package.
type ErrorUnsupportedType struct {
	t reflect.Type
}

// Error implements the error interface.
func (e ErrorUnsupportedType) Error() string {
	return fmt.Sprintf("unsupported type %v", e.t)
}

// ErrorWhileSettingConfig is returned when a configuration field cannot be set.
type ErrorWhileSettingConfig string

func newErrorWhileSettingConfig(v interface{}) ErrorWhileSettingConfig {
	return ErrorWhileSettingConfig(fmt.Sprintf("%s", v))
}

// Error implements the error interface.
func (e ErrorWhileSettingConfig) Error() string {
	return fmt.Sprintf("err while setting field %s", string(e))
}
