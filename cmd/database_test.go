package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Database Command", func() {
	Describe("addDBInitCommands", func() {
		It("adds init-db command to root command", func() {
			rootCmd := &cobra.Command{}
			addDBInitCommands(rootCmd)

			Expect(rootCmd.Commands()).To(HaveLen(1))

			initCmd := rootCmd.Commands()[0]
			Expect(initCmd.Use).To(Equal("init-db"))
			Expect(initCmd.Short).To(Equal("Initialize the database schema"))
		})

		It("init-db command has required flags", func() {
			rootCmd := &cobra.Command{}
			addDBInitCommands(rootCmd)

			initCmd := rootCmd.Commands()[0]

			// Check that flags exist with correct defaults
			Expect(initCmd.Flags().Lookup("driver")).ToNot(BeNil())
			Expect(initCmd.Flags().Lookup("driver").DefValue).To(Equal("pgx"))

			Expect(initCmd.Flags().Lookup("host")).ToNot(BeNil())
			Expect(initCmd.Flags().Lookup("host").DefValue).To(Equal("localhost"))

			Expect(initCmd.Flags().Lookup("port")).ToNot(BeNil())
			Expect(initCmd.Flags().Lookup("port").DefValue).To(Equal(""))

			Expect(initCmd.Flags().Lookup("username")).ToNot(BeNil())
			Expect(initCmd.Flags().Lookup("username").DefValue).To(Equal(""))

			Expect(initCmd.Flags().Lookup("password")).ToNot(BeNil())
			Expect(initCmd.Flags().Lookup("password").DefValue).To(Equal(""))

			Expect(initCmd.Flags().Lookup("database")).ToNot(BeNil())
			Expect(initCmd.Flags().Lookup("database").DefValue).To(Equal("ezauth"))

			Expect(initCmd.Flags().Lookup("sslmode")).ToNot(BeNil())
			Expect(initCmd.Flags().Lookup("sslmode").DefValue).To(Equal("disable"))
		})

		It("init-db command has required flags marked as required", func() {
			rootCmd := &cobra.Command{}
			addDBInitCommands(rootCmd)

			initCmd := rootCmd.Commands()[0]

			// Check that certain flags are required
			Expect(initCmd.Flags().Changed("driver")).To(BeFalse())
			Expect(initCmd.Flags().Changed("username")).To(BeFalse())
			Expect(initCmd.Flags().Changed("password")).To(BeFalse())
			Expect(initCmd.Flags().Changed("port")).To(BeFalse())
		})

		DescribeTable("init-db required flags validation",
			func(args []string, expectError bool) {
				rootCmd := &cobra.Command{}
				addDBInitCommands(rootCmd)
				rootCmd.SetArgs(append([]string{"init-db"}, args...))
				err := rootCmd.Execute()
				if expectError {
					Expect(err).To(HaveOccurred())
				} else {
					Expect(err).ToNot(HaveOccurred())
				}
			},
			Entry("missing all required flags", []string{}, true),
			Entry("missing username", []string{"--driver=pgx", "--password=secret", "--port=5432"}, true),
			Entry("missing password", []string{"--driver=pgx", "--username=postgres", "--port=5432"}, true),
			Entry("missing port", []string{"--driver=pgx", "--username=postgres", "--password=secret"}, true),
			Entry("missing driver", []string{"--username=postgres", "--password=secret", "--port=5432"}, true),
			Entry("all required flags provided", []string{
				"--driver=pgx",
				"--username=postgres",
				"--password=secret",
				"--port=5432",
			}, true),
			Entry("with optional sslmode", []string{
				"--driver=pgx",
				"--username=postgres",
				"--password=secret",
				"--port=5432",
				"--sslmode=require",
			}, true),
			Entry("with optional database", []string{
				"--driver=pgx",
				"--username=postgres",
				"--password=secret",
				"--port=5432",
				"--database=myapp",
			}, true),
		)
	})

	Describe("init-db ValidateDBName", func() {
		It("should reject invalid database name", func() {
			if os.Getenv("EZ_TEST_INITDB_INVALID_NAME") == "1" {
				rootCmd := &cobra.Command{}
				addDBInitCommands(rootCmd)
				rootCmd.SetArgs([]string{"init-db",
					"--driver=pgx",
					"--username=postgres",
					"--password=secret",
					"--port=5432",
					"--database=123-invalid",
				})
				if err := rootCmd.Execute(); err != nil {
					fmt.Fprintln(os.Stderr, err.Error())
					os.Exit(1)
				}
				os.Exit(0)
			}
			exe, err := os.Executable()
			Expect(err).ToNot(HaveOccurred())
			c := exec.Command(exe, "-test.run=TestMainSuite")
			c.Env = append(os.Environ(), "EZ_TEST_INITDB_INVALID_NAME=1")
			var stderr bytes.Buffer
			c.Stderr = &stderr
			err = c.Run()
			var exitErr *exec.ExitError
			Expect(errors.As(err, &exitErr)).To(BeTrue())
			Expect(exitErr.ExitCode()).To(Equal(1))
			Expect(stderr.String()).To(ContainSubstring("invalid database name"))
		})
	})

	Describe("bootstrap ValidateDBName", func() {
		It("should reject invalid database name", func() {
			if os.Getenv("EZ_TEST_BOOTSTRAP_INVALID_NAME") == "1" {
				rootCmd := &cobra.Command{}
				addBootstrapCommand(rootCmd)
				rootCmd.SetArgs([]string{"bootstrap",
					"--driver=pgx",
					"--db-user=postgres",
					"--db-password=secret",
					"--port=5432",
					"--database=123-invalid",
				})
				if err := rootCmd.Execute(); err != nil {
					fmt.Fprintln(os.Stderr, err.Error())
					os.Exit(1)
				}
				os.Exit(0)
			}
			exe, err := os.Executable()
			Expect(err).ToNot(HaveOccurred())
			c := exec.Command(exe, "-test.run=TestMainSuite")
			c.Env = append(os.Environ(), "EZ_TEST_BOOTSTRAP_INVALID_NAME=1")
			var stderr bytes.Buffer
			c.Stderr = &stderr
			err = c.Run()
			var exitErr *exec.ExitError
			Expect(errors.As(err, &exitErr)).To(BeTrue())
			Expect(exitErr.ExitCode()).To(Equal(1))
			Expect(stderr.String()).To(ContainSubstring("invalid database name"))
		})
	})
})
