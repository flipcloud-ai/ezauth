package secret_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSecretDriverSuite(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Secret Driver Suite")
}
