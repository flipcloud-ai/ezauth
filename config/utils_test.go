package config

import (
	"net/url"
	"reflect"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

type EP struct {
	Field1  *string
	Field2  *int
	Field3  *bool
	Field4  *int8
	Field5  *int16
	Field6  *int32
	Field7  *int64
	Field8  *uint8
	Field9  *uint16
	Field10 *uint32
	Field11 *uint64
	Field12 *uint
	Field13 *float32
	Field14 *float64
	Field15 *[]byte
	Field16 *uint64
	Field17 *uint
	Time    *time.Duration
}

type E struct {
	Field1  string
	Field2  int
	Field3  bool
	Field4  int8
	Field5  int16
	Field6  int32
	Field7  int64
	Field8  uint8
	Field9  uint16
	Field10 uint32
	Field11 uint64
	Field12 uint
	Field13 float32
	Field14 float64
	Field15 []byte
	Field16 uint64
	Field17 uint
	Time    time.Duration
}

type emptyStruct struct{}

type ptrElem struct{ X string }
type structWithPtrSlice struct {
	Items []*ptrElem
}

func noopFn(v reflect.Value) error { return nil }

var _ = Describe("Config Utils Test Suite", func() {
	Context("Utils test", func() {
		e := E{
			Field1:  "A",
			Field2:  2,
			Field3:  false,
			Field15: []byte("test"),
			Time:    1 * time.Hour,
		}
		ep := EP{}

		DescribeTable("value test",
			func(fieldName string, newValue string, expectValue any, expectOK bool, expectEqual bool) {
				// value type
				v := reflect.ValueOf(&e).Elem().FieldByName(fieldName)
				err := setValue(v, newValue, noopFn)
				Expect(err == nil).To(Equal(expectOK))
				Expect(v.Equal(reflect.ValueOf(expectValue))).To(Equal(expectEqual))

				// pointer type
				vp := reflect.ValueOf(&ep).Elem().FieldByName(fieldName)
				err = setValue(vp, newValue, noopFn)
				Expect(err == nil).To(Equal(expectOK))
				Expect(vp.Elem().Equal(reflect.ValueOf(expectValue))).To(Equal(expectEqual))
			},
			Entry("string value", "Field1", "new_value", "new_value", true, true),
			Entry("int value", "Field2", "3", 3, true, true),
			Entry("bool value", "Field3", "true", true, true, true),
			Entry("int8 value", "Field4", "4", int8(4), true, true),
			Entry("int16 value", "Field5", "5", int16(5), true, true),
			Entry("int32 value", "Field6", "6", int32(6), true, true),
			Entry("int64 value", "Field7", "7", int64(7), true, true),
			Entry("uint8 value", "Field8", "4", uint8(4), true, true),
			Entry("uint16 value", "Field9", "5", uint16(5), true, true),
			Entry("uint32 value", "Field10", "6", uint32(6), true, true),
			Entry("uint64 value", "Field11", "7", uint64(7), true, true),
			Entry("uint value", "Field12", "100", uint(100), true, true),
			Entry("float32 value", "Field13", "3.1314", float32(3.1314), true, true),
			Entry("float64 value", "Field14", "2.333333", float64(2.333333), true, true),
			Entry("time duration value", "Time", "1h", 1*time.Hour, true, true),
		)

		It("returns nil for immutable struct values and does not mutate", func() {
			err := setValue(reflect.ValueOf(&e), "new_value", noopFn)
			Expect(err).ToNot(HaveOccurred())
			Expect(reflect.ValueOf(&e).Equal(reflect.ValueOf("new_value"))).To(BeFalse())

			err = setValue(reflect.ValueOf(&ep), "new_value", noopFn)
			Expect(err).ToNot(HaveOccurred())
			Expect(reflect.ValueOf(&ep).Equal(reflect.ValueOf("new_value"))).To(BeFalse())
		})

		It("sets []byte value", func() {
			var v []byte
			err := setValue(reflect.ValueOf(&v).Elem(), "test_bytes", noopFn)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(v)).To(Equal("test_bytes"))
		})
		It("sets *url.URL value", func() {
			var v *url.URL
			err := setValue(reflect.ValueOf(&v).Elem(), "https://example.com", noopFn)
			Expect(err).ToNot(HaveOccurred())
			Expect(v.String()).To(Equal("https://example.com"))
		})
	})

	Context("setValue error paths", func() {
		It("returns error for invalid duration", func() {
			var d time.Duration
			err := setValue(reflect.ValueOf(&d).Elem(), "not-a-duration", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse duration"))
		})
		It("returns error for invalid bool", func() {
			var b bool
			err := setValue(reflect.ValueOf(&b).Elem(), "not-a-bool", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse bool"))
		})
		It("returns error for invalid int8", func() {
			var i int8
			err := setValue(reflect.ValueOf(&i).Elem(), "not-an-int", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse int8"))
		})
		It("returns error for invalid int16", func() {
			var i int16
			err := setValue(reflect.ValueOf(&i).Elem(), "invalid", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse int16"))
		})
		It("returns error for invalid int32", func() {
			var i int32
			err := setValue(reflect.ValueOf(&i).Elem(), "invalid", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse int32"))
		})
		It("returns error for invalid int64", func() {
			var i int64
			err := setValue(reflect.ValueOf(&i).Elem(), "invalid", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse int64"))
		})
		It("returns error for invalid int", func() {
			var i int
			err := setValue(reflect.ValueOf(&i).Elem(), "invalid", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse int"))
		})
		It("returns error for invalid uint8", func() {
			var u uint8
			err := setValue(reflect.ValueOf(&u).Elem(), "invalid", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse uint8"))
		})
		It("returns error for invalid uint16", func() {
			var u uint16
			err := setValue(reflect.ValueOf(&u).Elem(), "invalid", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse uint16"))
		})
		It("returns error for invalid uint32", func() {
			var u uint32
			err := setValue(reflect.ValueOf(&u).Elem(), "invalid", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse uint32"))
		})
		It("returns error for invalid uint64", func() {
			var u uint64
			err := setValue(reflect.ValueOf(&u).Elem(), "invalid", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse uint64"))
		})
		It("returns error for invalid uint", func() {
			var u uint
			err := setValue(reflect.ValueOf(&u).Elem(), "invalid", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse uint"))
		})
		It("returns error for invalid float32", func() {
			var f float32
			err := setValue(reflect.ValueOf(&f).Elem(), "invalid", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse float32"))
		})
		It("returns error for invalid float64", func() {
			var f float64
			err := setValue(reflect.ValueOf(&f).Elem(), "invalid", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse float64"))
		})
		It("returns error for unsupported slice element type", func() {
			s := struct{ Nums []int }{Nums: []int{1}}
			err := setValue(reflect.ValueOf(&s).Elem().FieldByName("Nums"), "", noopFn)
			Expect(err).To(HaveOccurred())
			_, ok := err.(ErrorUnsupportedType)
			Expect(ok).To(BeTrue())
		})
		It("returns error for unsupported type (map)", func() {
			m := map[string]string{}
			err := setValue(reflect.ValueOf(&m).Elem(), "anything", noopFn)
			Expect(err).To(HaveOccurred())
			_, ok := err.(ErrorUnsupportedType)
			Expect(ok).To(BeTrue())
		})
		It("returns nil for struct with zero fields", func() {
			es := emptyStruct{}
			err := setValue(reflect.ValueOf(&es).Elem(), "", noopFn)
			Expect(err).ToNot(HaveOccurred())
		})
		It("returns nil for slice of pointers with noop fn", func() {
			s := structWithPtrSlice{
				Items: []*ptrElem{{X: "a"}, {X: "b"}},
			}
			err := setValue(reflect.ValueOf(&s).Elem().FieldByName("Items"), "", noopFn)
			Expect(err).ToNot(HaveOccurred())
		})
		It("returns fn error for slice of pointers", func() {
			s := structWithPtrSlice{
				Items: []*ptrElem{{X: "a"}},
			}
			err := setValue(reflect.ValueOf(&s).Elem().FieldByName("Items"), "", func(v reflect.Value) error {
				return ErrorUnsupportedType{}
			})
			Expect(err).To(HaveOccurred())
		})

		It("returns error for invalid *url.URL", func() {
			var u *url.URL
			err := setValue(reflect.ValueOf(&u).Elem(), "http://example.com/%ZZ", noopFn)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("parse url"))
		})
	})
})
