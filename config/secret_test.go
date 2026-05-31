package config

import (
	"reflect"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("SecretRef", func() {
	Describe("NewResolvedSecretRef", func() {
		It("creates a SecretRef with pre-resolved bytes", func() {
			sv := NewResolvedSecretRef([]byte("hello"))
			Expect(sv.Bytes()).To(Equal([]byte("hello")))
		})

		It("creates a SecretRef that is not zero", func() {
			sv := NewResolvedSecretRef([]byte("data"))
			Expect(sv.IsZero()).To(BeFalse())
		})

		It("copies input bytes so mutations do not affect the SecretRef", func() {
			orig := []byte("original-data")
			sv := NewResolvedSecretRef(orig)
			orig[0] = 'X'
			Expect(sv.Bytes()).To(Equal([]byte("original-data")))
		})
	})

	Describe("SetRaw", func() {
		It("stores bytes accessible via Bytes()", func() {
			var sr SecretRef
			sr.SetRaw([]byte("secret"))
			Expect(sr.Bytes()).To(Equal([]byte("secret")))
		})

		It("copies input so mutations do not affect the SecretRef", func() {
			b := []byte("mutable")
			var sr SecretRef
			sr.SetRaw(b)
			b[0] = 'X'
			Expect(sr.Bytes()).To(Equal([]byte("mutable")))
		})
	})

	Describe("IsZero", func() {
		It("returns true for a zero-value SecretRef", func() {
			sv := SecretRef{}
			Expect(sv.IsZero()).To(BeTrue())
		})

		It("returns false when raw bytes are set", func() {
			sv := SecretRef{raw: []byte("data")}
			Expect(sv.IsZero()).To(BeFalse())
		})

		It("returns false when Type is set", func() {
			sv := SecretRef{Type: "file"}
			Expect(sv.IsZero()).To(BeFalse())
		})

		It("returns false when Path is set", func() {
			sv := SecretRef{Path: "/some/path"}
			Expect(sv.IsZero()).To(BeFalse())
		})
	})

	Describe("Bytes", func() {
		It("returns nil for a zero-value SecretRef", func() {
			sv := SecretRef{}
			Expect(sv.Bytes()).To(BeNil())
		})

		It("returns the raw bytes when set", func() {
			sv := SecretRef{raw: []byte{0x01, 0x02, 0x03}}
			Expect(sv.Bytes()).To(Equal([]byte{0x01, 0x02, 0x03}))
		})
	})
})

var _ = Describe("SecretRefDecodeHookFunc", func() {
	var hook interface{}

	BeforeEach(func() {
		hook = SecretRefDecodeHookFunc()
	})

	It("returns data unchanged when target type is not SecretRef", func() {
		fn, ok := hook.(func(reflect.Type, reflect.Type, interface{}) (interface{}, error))
		Expect(ok).To(BeTrue())

		result, err := fn(reflect.TypeOf(""), reflect.TypeOf(""), "hello")
		Expect(err).ToNot(HaveOccurred())
		Expect(result).To(Equal("hello"))
	})

	Describe("from string", func() {
		It("uses the string value as-is (plaintext)", func() {
			fn := hook.(func(reflect.Type, reflect.Type, interface{}) (interface{}, error))

			result, err := fn(reflect.TypeOf(""), reflect.TypeOf(SecretRef{}), "my-plain-secret")
			Expect(err).ToNot(HaveOccurred())

			sv, ok := result.(SecretRef)
			Expect(ok).To(BeTrue())
			Expect(sv.Bytes()).To(Equal([]byte("my-plain-secret")))
		})

		It("accepts any string including special characters", func() {
			fn := hook.(func(reflect.Type, reflect.Type, interface{}) (interface{}, error))

			result, err := fn(reflect.TypeOf(""), reflect.TypeOf(SecretRef{}), "not-base64-!!!")
			Expect(err).ToNot(HaveOccurred())

			sv, ok := result.(SecretRef)
			Expect(ok).To(BeTrue())
			Expect(sv.Bytes()).To(Equal([]byte("not-base64-!!!")))
		})

		It("returns zero SecretRef for empty string", func() {
			fn := hook.(func(reflect.Type, reflect.Type, interface{}) (interface{}, error))

			result, err := fn(reflect.TypeOf(""), reflect.TypeOf(SecretRef{}), "")
			Expect(err).ToNot(HaveOccurred())

			sv, ok := result.(SecretRef)
			Expect(ok).To(BeTrue())
			Expect(sv.IsZero()).To(BeTrue())
		})
	})

	Describe("from map", func() {
		It("creates SecretRef from map with type field", func() {
			fn := hook.(func(reflect.Type, reflect.Type, interface{}) (interface{}, error))

			result, err := fn(reflect.TypeOf(map[string]interface{}{}), reflect.TypeOf(SecretRef{}),
				map[string]interface{}{"type": "file", "path": "/etc/secret", "key": "mykey"})
			Expect(err).ToNot(HaveOccurred())

			sv, ok := result.(SecretRef)
			Expect(ok).To(BeTrue())
			Expect(sv.Type).To(Equal("file"))
			Expect(sv.Path).To(Equal("/etc/secret"))
			Expect(sv.Key).To(Equal("mykey"))
			Expect(sv.IsZero()).To(BeFalse())
		})

		It("handles missing optional fields in map", func() {
			fn := hook.(func(reflect.Type, reflect.Type, interface{}) (interface{}, error))

			result, err := fn(reflect.TypeOf(map[string]interface{}{}), reflect.TypeOf(SecretRef{}),
				map[string]interface{}{})
			Expect(err).ToNot(HaveOccurred())

			sv, ok := result.(SecretRef)
			Expect(ok).To(BeTrue())
			Expect(sv.Type).To(Equal(""))
			Expect(sv.Path).To(Equal(""))
			Expect(sv.Key).To(Equal(""))
		})
	})

	Describe("from unsupported type", func() {
		It("returns error for integer input", func() {
			fn := hook.(func(reflect.Type, reflect.Type, interface{}) (interface{}, error))

			_, err := fn(reflect.TypeOf(0), reflect.TypeOf(SecretRef{}), 42)
			Expect(err).To(HaveOccurred())
			Expect(err.Error()).To(ContainSubstring("cannot decode int into SecretRef"))
		})

		It("returns error for boolean input", func() {
			fn := hook.(func(reflect.Type, reflect.Type, interface{}) (interface{}, error))

			_, err := fn(reflect.TypeOf(false), reflect.TypeOf(SecretRef{}), true)
			Expect(err).To(HaveOccurred())
		})
	})
})
