package models

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"time"

	"github.com/lib/pq"
	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/flipcloud-ai/ezauth/pkg/utils"
)

// OIDCDB holds the OIDC-specific endpoint configuration stored in the database.
type OIDCDB struct {
	Issuer               *datatypes.URL `gorm:"type:text" json:"issuer"`
	AuthURL              *datatypes.URL `gorm:"type:text" json:"authorization_endpoint"`
	TokenURL             *datatypes.URL `gorm:"type:text" json:"token_endpoint"`
	JWKsURL              *datatypes.URL `gorm:"type:text" json:"jwks_uri"`
	UserInfoURL          *datatypes.URL `gorm:"type:text" json:"userinfo_endpoint"`
	RevocationURL        *datatypes.URL `gorm:"type:text" json:"revocation_endpoint"`
	CodeChallengeMethod  pq.StringArray `gorm:"type:text[]" json:"code_challenge_methods_supported"`
	SupportedSigningAlgs pq.StringArray `gorm:"type:text[]" json:"id_token_signing_alg_values_supported"`
	ProtectedResource    *datatypes.URL `gorm:"type:text" json:"protected_resource"`
}

// LoginParameters stores arbitrary key-value login parameter data as a JSONB column.
type LoginParameters map[string][]string

// GormDataType returns the database column type for LoginParameters.
func (LoginParameters) GormDataType() string {
	return "JSONB"
}

// Scan implements the sql.Scanner interface for LoginParameters.
func (l *LoginParameters) Scan(value any) error {
	var bytes []byte
	switch v := value.(type) {
	case []byte:
		bytes = v
	case string:
		bytes = []byte(v)
	default:
		return fmt.Errorf("failed to unmarshal JSONB value: %v", value)
	}
	if err := json.Unmarshal(bytes, l); err != nil {
		return fmt.Errorf("unmarshal login parameters: %w", err)
	}
	return nil
}

// Value implements the driver.Valuer interface for LoginParameters.
func (l LoginParameters) Value() (driver.Value, error) {
	b, err := json.Marshal(l)
	if err != nil {
		return nil, fmt.Errorf("marshal login parameters: %w", err)
	}
	return b, nil
}

// ProviderDB represents the ORM model for OAuth2/OIDC provider configuration.
type ProviderDB struct {
	ProviderName      string         `gorm:"primaryKey;unique;not null;size:256;default:null" json:"provider_name"`
	Type              string         `gorm:"not null;size:64;default:null" json:"type"`
	RedirectURL       *datatypes.URL `gorm:"type:text;not null;default:null" json:"redirect_url"`
	DeviceAuthURL     *datatypes.URL `gorm:"type:text" json:"device_auth_url"`
	ValidateURL       *datatypes.URL `gorm:"type:text" json:"validate_url"`
	AllowedGroups     pq.StringArray `gorm:"type:text[]" json:"allowed_groups"`
	AdminGroup        string         `gorm:"column:admin_group;type:varchar(128)" json:"admin_group,omitempty"`
	ClaimsFromProfile bool           `json:"claims_from_profile"`

	OIDCDB

	Scope        string `gorm:"not null;type:text;default:null" json:"scope"`
	ClientID     string `gorm:"not null;size:512;default:null" json:"client_id"`
	ClientSecret string `gorm:"not null;size:512;default:null" json:"client_secret"`
	UserClaim    string `json:"user_claim"`

	SkipNonce bool `json:"skip_nonce"`

	LoginParameters LoginParameters `gorm:"type:jsonb" json:"login_parameters"`

	CreatedAt time.Time `gorm:"column:created_at;autoCreateTime;default:now();not null" json:"created_at"`
	UpdatedAt time.Time `gorm:"column:updated_at;autoUpdateTime;default:now();not null" json:"updated_at"`

	Enabled bool `gorm:"type:bool" json:"enabled"`
}

// TableName returns the database table name for ProviderDB.
func (ProviderDB) TableName() string {
	return "providers"
}

// BeforeCreate validates ProviderDB fields before persisting to the database.
func (p *ProviderDB) BeforeCreate(tx *gorm.DB) error {
	if !utils.IsValidName(p.ProviderName, 64) {
		return fmt.Errorf("validation error: invalid provider name")
	}
	if p.Issuer == nil && (p.AuthURL != nil || p.TokenURL != nil || p.JWKsURL != nil || p.UserInfoURL != nil) {
		return fmt.Errorf("validation error: issuer is required when OIDC endpoints are provided")
	}
	if p.ClientID == "" || p.ClientSecret == "" {
		return fmt.Errorf("validation error: client_id and client_secret are required")
	}
	return nil
}

func convertField(srcVal reflect.Value, dataVal reflect.Value) error {
	if dataVal.Type().String() == "*url.URL" && srcVal.Type().String() == "*datatypes.URL" && !srcVal.IsNil() {
		urlStr := srcVal.Interface().(*datatypes.URL).String()
		if urlStr != "" {
			parsedURL, err := url.Parse(urlStr)
			if err != nil {
				return fmt.Errorf("parse url %q: %w", urlStr, err)
			}
			dataVal.Set(reflect.ValueOf(parsedURL))
		}
	} else if srcVal.Type().String() == "pq.StringArray" {
		if dataVal.Type().String() == "[]string" {
			strArray := srcVal.Interface().(pq.StringArray)
			dataVal.Set(reflect.ValueOf([]string(strArray)))
		} else if dataVal.Type().String() == "string" {
			strArray := srcVal.Interface().(pq.StringArray)
			s := strings.Join([]string(strArray), ",")
			dataVal.SetString(s)
		}
	} else if srcVal.Type().String() == "models.LoginParameters" && dataVal.Type().String() == "map[string][]string" {
		loginParams := srcVal.Interface().(LoginParameters)
		dataVal.Set(reflect.ValueOf(map[string][]string(loginParams)))
	} else if srcVal.Type().String() == "map[string][]string" && dataVal.Type().String() == "models.LoginParameters" {
		loginParams := srcVal.Interface().(map[string][]string)
		dataVal.Set(reflect.ValueOf(LoginParameters(loginParams)))
	} else if srcVal.Type().String() == "string" {
		s := srcVal.Interface().(string)
		if dataVal.Type().String() == "*datatypes.URL" {
			u, err := url.Parse(s)
			if err != nil {
				return fmt.Errorf("parse url %q: %w", s, err)
			}
			du := datatypes.URL(*u)
			dataVal.Set(reflect.ValueOf(&du))
		} else if dataVal.Type().String() == "time.Duration" {
			if s == "" {
				return nil
			}
			d, err := time.ParseDuration(s)
			if err != nil {
				return fmt.Errorf("parse duration %q: %w", s, err)
			}
			dataVal.Set(reflect.ValueOf(d))
		}
	} else if srcVal.Type().String() == "[]string" && dataVal.Type().String() == "pq.StringArray" {
		strArray := srcVal.Interface().([]string)
		dataVal.Set(reflect.ValueOf(pq.StringArray(strArray)))
	}
	return nil
}

func reflectStruct(val reflect.Value, dataVal reflect.Value) error {
	if !dataVal.CanSet() {
		return nil
	}
	// handle pointer
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return nil
		}
		if dataVal.Kind() == reflect.Pointer {
			// convert different struct type
			if dataVal.Type().String() != val.Type().String() {
				return convertField(val, dataVal)
			}
			dataVal.Set(val)
			return nil
		}
		val = reflect.Indirect(val)
	}

	for i := 0; i < dataVal.NumField(); i++ {
		fieldName := dataVal.Type().Field(i).Name
		srcVal := val.FieldByName(fieldName)
		// handle OIDCConfig for DB to Config conversion
		if fieldName == "OIDCConfig" {
			srcVal = val.FieldByName("OIDCDB")
		}
		// handle OIDCConfigRequest for DTO to DB conversion
		if fieldName == "OIDCDB" {
			srcVal = val.FieldByName("OIDCConfigRequest")
		}
		if !srcVal.IsValid() || !dataVal.Field(i).CanSet() {
			continue
		}
		if dataVal.Field(i).Type().String() != srcVal.Type().String() {
			isStruct := srcVal.Kind() == reflect.Struct
			isPtr := srcVal.Kind() == reflect.Pointer
			isStructPointer := isPtr && srcVal.Type().Elem().Kind() == reflect.Struct
			if isStruct || isStructPointer {
				err := reflectStruct(srcVal, dataVal.Field(i))
				if err != nil {
					return err
				}
				continue
			} else if isPtr {
				if srcVal.IsNil() {
					continue
				} else {
					srcVal = reflect.Indirect(srcVal)
				}
			}
			if dataVal.Field(i).Type().String() == srcVal.Type().String() {
				dataVal.Field(i).Set(srcVal)
			} else {
				err := convertField(srcVal, dataVal.Field(i))
				if err != nil {
					return fmt.Errorf("error parsing URL for field %s: %v", fieldName, err)
				}
			}
		} else {
			if dataVal.Field(i).CanSet() {
				dataVal.Field(i).Set(val.FieldByName(dataVal.Type().Field(i).Name))
			}
		}
	}

	return nil
}

// ParseData copies fields from source into target by matching field names via reflection.
func ParseData(source any, target any) error {
	val := reflect.ValueOf(source)
	if !val.IsValid() {
		return fmt.Errorf("source is nil")
	}
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return fmt.Errorf("source pointer is nil")
		}
		val = val.Elem()
	}
	dataVal := reflect.ValueOf(target)
	if !dataVal.IsValid() {
		return fmt.Errorf("target is nil")
	}
	if dataVal.Kind() == reflect.Pointer {
		if dataVal.IsNil() {
			return fmt.Errorf("target pointer is nil")
		}
		dataVal = dataVal.Elem()
	}
	if val.Kind() != reflect.Struct {
		return fmt.Errorf("source must be a struct or pointer to struct, got %s", val.Kind())
	}
	if dataVal.Kind() != reflect.Struct {
		return fmt.Errorf("target must be a struct or pointer to struct, got %s", dataVal.Kind())
	}
	return reflectStruct(val, dataVal)
}
