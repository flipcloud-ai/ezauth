package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/mitchellh/go-homedir"

	"github.com/spf13/cobra"
	flag "github.com/spf13/pflag"
	"github.com/spf13/viper"

	ezutils "github.com/flipcloud-ai/ezauth/pkg/utils"
)

var (
	homeDir, _            = homedir.Dir()
	configSearchLocations = []string{
		ezutils.Getenv("EZAUTH_CONFIG_PATH", "/opt/ezauth"),
		filepath.Join(homeDir, "ez"),
		".",
	}
)

// AuditConfig controls the in-memory ring buffer and background flush behaviour.
type AuditConfig struct {
	Enabled       *bool         `mapstructure:"enabled" default:"true"`
	BufferSize    int           `mapstructure:"buffer_size" default:"500"`
	FlushInterval time.Duration `mapstructure:"flush_interval" default:"5m"`
	File          string        `mapstructure:"file"`
	MaxFileSize   int64         `mapstructure:"max_file_size" default:"104857600"` // 100 MiB
}

// Options is the top-level configuration struct populated from file, env, and CLI flags.
type Options struct {
	Log      LogConfig        `mapstructure:"log"`
	Server   ServerConfig     `mapstructure:"server"`
	Database DatabaseConfig   `mapstructure:"database"`
	Auth     AuthConfig       `mapstructure:"auth"`
	Access   AccessConfig     `mapstructure:"access"`
	Cache    StoreCacheConfig `mapstructure:"cache"`
	Audit    AuditConfig      `mapstructure:"audit"`
}

// LogConfig controls the logging level, format, and optional log file path.
type LogConfig struct {
	Level  string `mapstructure:"level" default:"info" flag:"log-level"`
	Format string `mapstructure:"format" default:"json" flag:"log-format"`
	Path   string `mapstructure:"path" flag:"log-path"`
}

// LoadConfiguration reads the config file, environment variables, and CLI flags
// into an Options struct. CLI flags override env vars, which override file values.
func LoadConfiguration(cmd *cobra.Command) (*Options, error) {
	v := viper.New()
	rawVal := &Options{}
	var err error

	cfgFile := cmd.Flags().Lookup("config")

	if cfgFile != nil {
		v.SetConfigFile(cfgFile.Value.String())
	} else {
		v.SetConfigName("config")
		v.SetConfigType("yaml")
		for _, searchLocation := range configSearchLocations {
			v.AddConfigPath(searchLocation)
		}
	}

	err = v.ReadInConfig()
	if err == nil {
		fmt.Println("Using config file: ", v.ConfigFileUsed())
	} else {
		_, ok := err.(viper.ConfigFileNotFoundError)
		if ok || errors.Is(err, os.ErrNotExist) {
			// If config flag was explicitly set but file doesn't exist, fail
			if cfgFile != nil && cfgFile.Changed {
				return nil, fmt.Errorf("config file %s does not exist", cfgFile.Value.String())
			}
			fmt.Println("Can't find configure file, using default")
		} else {
			return nil, fmt.Errorf("loading config file: %w", err)
		}
	}

	cmdFlags := make(map[string]*flag.Flag, 0)
	cmd.Flags().VisitAll(func(flag *flag.Flag) {
		flagName := flag.Name
		if flagName != "config" && flagName != "help" && flag.Changed {
			cmdFlags[flagName] = flag
		}
	})

	for _, e := range os.Environ() {
		if strings.HasPrefix(e, "EZ_") {
			s := strings.Split(e, "=")
			envVal := strings.Join(s[1:], "=")
			key := strings.TrimPrefix(
				strings.ToLower(
					strings.ReplaceAll(
						s[0], "_", "."),
				),
				"ez.",
			)
			v.Set(key, envVal)
		}
	}

	if err = v.Unmarshal(rawVal, viper.DecodeHook(
		mapstructure.ComposeDecodeHookFunc(
			SecretRefDecodeHookFunc(),
			mapstructure.StringToTimeDurationHookFunc(),
			mapstructure.StringToSliceHookFunc(","),
			mapstructure.StringToURLHookFunc(),
		),
	)); err == nil {
		err = parseCfg(rawVal, cmdFlags)
	}

	// Apply debug flag after flag parsing so it takes precedence
	if cmd.Flags().Lookup("debug") != nil && cmd.Flags().Lookup("debug").Value.String() == "true" {
		rawVal.Log.Level = "debug"
	}

	if err != nil {
		return nil, fmt.Errorf("unmarshal configuration: %w", err)
	}

	// --database-password flag injects plaintext directly; only apply if explicitly set.
	if f := cmd.Flags().Lookup("database-password"); f != nil && f.Changed {
		rawVal.Database.Password = NewResolvedSecretRef([]byte(f.Value.String()))
	}

	if cmd.Flags().Lookup("client-id") != nil && cmd.Flags().Lookup("client-id").Value.String() != "" && cmd.Flags().Lookup("client-secret") != nil && cmd.Flags().Lookup("client-secret").Value.String() != "" {
		providerName := "oauth2"
		if cmd.Flags().Lookup("provider-name") != nil && cmd.Flags().Lookup("provider-name").Value.String() != "" {
			providerName = cmd.Flags().Lookup("provider-name").Value.String()
		}
		var existing *ProviderConfig
		for _, p := range rawVal.Auth.Provider {
			if p.ProviderName == providerName {
				existing = p
				break
			}
		}
		if existing != nil {
			existing.ClientID = cmd.Flags().Lookup("client-id").Value.String()
			existing.ClientSecret = cmd.Flags().Lookup("client-secret").Value.String()
		} else {
			p := &ProviderConfig{
				ProviderName: providerName,
				ClientID:     cmd.Flags().Lookup("client-id").Value.String(),
				ClientSecret: cmd.Flags().Lookup("client-secret").Value.String(),
			}
			if err = parseCfg(p, cmdFlags); err != nil {
				return nil, fmt.Errorf("invalid provider configuration: %w", err)
			}
			rawVal.Auth.Provider = append(rawVal.Auth.Provider, p)
		}
	}
	return rawVal, nil
}

func parseCfg(i interface{}, cmdFLags map[string]*flag.Flag) error {
	val := reflect.ValueOf(i)
	if val.Kind() != reflect.Pointer {
		return newErrNotAStructPointer(i)
	}

	// Make sure the pointer is pointing to a struct.
	ref := val.Elem()
	if ref.Kind() != reflect.Struct {
		return newErrNotAStructPointer(i)
	}

	return parseFields(ref, cmdFLags)
}

func parseFields(v reflect.Value, cmdFlags map[string]*flag.Flag) error {
	// Iterate over the fields of the configuration struct using reflection
	// and set the default value for each field if the field is not provided
	for i := 0; i < v.NumField(); i++ {
		val := v.Field(i)
		field := v.Type().Field(i)
		err := parseDefaultField(val, field, cmdFlags)
		if err != nil {
			return err
		}
		err = parseFlagField(val, field, cmdFlags)
		if err != nil {
			return err
		}
	}
	return nil
}

func parseDefaultField(value reflect.Value, field reflect.StructField, cmdFLags map[string]*flag.Flag) error {
	tagVal := field.Tag.Get("default")

	isPtrSlice := value.Kind() == reflect.Slice && value.Type().Elem().Kind() == reflect.Pointer
	isStruct := value.Kind() == reflect.Struct
	isStructPointer := value.Kind() == reflect.Pointer && value.Type().Elem().Kind() == reflect.Struct

	if ((tagVal == "" || tagVal == "-") || !value.IsZero()) && !isStruct && !isStructPointer && !isPtrSlice {
		return nil
	}

	err := setValue(value, tagVal, func(v reflect.Value) error {
		if v.Kind() == reflect.Pointer {
			if v.Type().Elem().Kind() == reflect.Struct {
				// If value is pointer to struct, indirect the ptr and iterate over the struct
				v = reflect.Indirect(v)
			}
		}
		// Iterate over the fields of the configuration struct using reflection
		// and set the default value for each field if the field is not provided
		for i := 0; i < v.NumField(); i++ {
			err := parseDefaultField(v.Field(i), v.Type().Field(i), cmdFLags)
			if err != nil {
				return err
			}
		}
		return nil
	})
	return err
}

func parseFlagField(
	value reflect.Value,
	field reflect.StructField,
	cmdFLags map[string]*flag.Flag,
) error {
	tagVal := field.Tag.Get("flag")

	isStruct := value.Kind() == reflect.Struct
	isStructPointer := value.Kind() == reflect.Pointer && value.Type().Elem().Kind() == reflect.Struct

	if tagVal == "" || tagVal == "-" {
		if (!isStruct && !isStructPointer) || !value.CanSet() {
			return nil
		}
	}

	if !value.CanSet() {
		return newErrorUnsettable(field.Name)
	}

	if isStruct || isStructPointer {
		v := value
		if value.Kind() == reflect.Pointer {
			if value.IsNil() {
				return nil
			}
			v = reflect.Indirect(value)
		}
		// Iterate over the fields of the configuration struct using reflection
		// and set the default value for each field if the field is not provided
		for i := 0; i < v.NumField(); i++ {
			err := parseFlagField(v.Field(i), v.Type().Field(i), cmdFLags)
			if err != nil {
				return err
			}
		}
	} else {
		flag, ok := cmdFLags[tagVal]
		if !ok {
			return nil
		}
		if err := setValue(value, flag.Value.String(), func(v reflect.Value) error {
			return newErrorWhileSettingConfig(v.String())
		}); err != nil {
			return err
		}
	}

	return nil
}
