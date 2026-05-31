package ezerror_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestXwError(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "XwError Suite")
}
