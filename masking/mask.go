package masking

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
)

type SetMaskSensitive struct {
	veryHigh []string
	High     []string
	Medium   []string
	Low      []string
}

// password "******"
func (s *MaskSensitive) SetVeryHigh(fields ...string) {
	s.MaskLevelVeryHigh = append(s.MaskLevelVeryHigh, fields...)
}

// mobileNO "XX-XXX-XX21"
func (s *MaskSensitive) SetHigh(fields ...string) {
	s.MaskLevelHigh = append(s.MaskLevelHigh, fields...)
}

// Email "t***@test.com"
func (s *MaskSensitive) SetMedium(fields ...string) {
	s.MaskLevelMedium = append(s.MaskLevelMedium, fields...)
}

// username "uw***we"
func (s *MaskSensitive) SetLow(fields ...string) {
	s.MaskLevelLow = append(s.MaskLevelLow, fields...)
}

func NewMaskSensitive() *MaskSensitive {
	var level SetMaskSensitive
	level.veryHigh = append(level.veryHigh, "Password")
	level.High = append(level.High, "mobileNO", "phone")
	level.Medium = append(level.Medium, "Email")
	level.Low = append(level.Low, "Username")

	return &MaskSensitive{
		MaskLevelVeryHigh: level.veryHigh,
		MaskLevelHigh:     level.High,
		MaskLevelMedium:   level.Medium,
		MaskLevelLow:      level.Low,
	}
}

type MaskSensitive struct {
	MaskLevelVeryHigh []string
	MaskLevelHigh     []string
	MaskLevelMedium   []string
	MaskLevelLow      []string
}

// censorship
func (m *MaskSensitive) MaskSensitiveData(data any) any {
	val := reflect.ValueOf(data)
	// Handle structs
	if val.Kind() == reflect.Struct {
		result := reflect.New(val.Type()).Elem()
		for i := 0; i < val.NumField(); i++ {
			fieldName := val.Type().Field(i).Name
			fieldValue := val.Field(i).Interface()
			fieldValue = m.checkFieldSensitive(fieldName, fieldValue)
			result.Field(i).Set(reflect.ValueOf(fieldValue))
		}

		return result.Interface()
	}

	// Handle maps
	if val.Kind() == reflect.Map {
		result := reflect.MakeMap(val.Type())
		for _, key := range val.MapKeys() {
			fieldName := key.Interface().(string)
			fieldValue := val.MapIndex(key).Interface()
			fieldValue = m.checkFieldSensitive(fieldName, fieldValue)
			result.SetMapIndex(key, reflect.ValueOf(fieldValue))
		}

		return result.Interface()
	}

	if val.Kind() == reflect.Slice {
		result := reflect.MakeSlice(val.Type(), val.Len(), val.Len())
		for i := 0; i < val.Len(); i++ {
			fieldValue := val.Index(i).Interface()
			fieldValue = m.MaskSensitiveData(fieldValue)
			result.Index(i).Set(reflect.ValueOf(fieldValue))
		}
		return result.Interface()
	}

	// Handle ptrs
	if val.Kind() == reflect.Ptr {
		return m.MaskSensitiveData(val.Elem().Interface())
	}

	// Unsupported type, return as-is
	return data
}

func (m *MaskSensitive) checkFieldSensitive(fieldName string, fieldValue any) any {
	if contains(m.MaskLevelVeryHigh, fieldName) {
		fieldValue = maskPassword(fieldValue.(string))
	} else if contains(m.MaskLevelHigh, fieldName) {
		fieldValue = MaskMobileNO(fieldValue.(string), "X")
	} else if contains(m.MaskLevelMedium, fieldName) {
		fieldValue = maskValue(fieldValue)
	} else if contains(m.MaskLevelLow, fieldName) {
		fieldValue = maskMiddleCharacters(fieldValue.(string), 2, 2)
	} else {
		fieldValue = m.MaskSensitiveData(fieldValue)
	}
	return fieldValue
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.EqualFold(s, item) {
			return true
		}
	}
	return false
}

func maskValue(value interface{}) interface{} {
	switch v := value.(type) {
	case string:
		return maskString(v)
	default:
		return value
	}
}

func maskPassword(v string) string {
	if len(v) < 1 {
		return v
	}
	return "******"
}

func maskString(input string) string {
	if isValidEmail(input) {
		return maskEmail(input)
	}
	return maskMiddleCharacters(input, 3, 0)
}

func ValidateBirthday(birthday string) (int64, error) {
	// birthday := "1997-05-26"
	parsedBirthday, err := time.Parse("2006-01-02", birthday)
	if err != nil {
		return 0, fmt.Errorf("error parsing birthday: %w", err)
	}

	timestamp := parsedBirthday.Unix()
	return timestamp, nil
}

func isValidEmail(email string) bool {
	emailRegex := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	regex := regexp.MustCompile(emailRegex)
	return regex.MatchString(email)
}

func maskEmail(email string) string {
	parts := strings.Split(email, "@")
	localPart, domain := parts[0], parts[1]
	maskedLocalPart := string(localPart[0]) + strings.Repeat("*", len(localPart)-1)
	maskedEmail := fmt.Sprintf("%s@%s", maskedLocalPart, domain)

	return maskedEmail
}

func MaskMobileNO(mobileNumber string, mask string) string {
	if len(mobileNumber) < 2 {
		return mobileNumber
	}
	pattern := "***-***-**"
	masked := strings.NewReplacer("*", mask).Replace(pattern)
	return masked + mobileNumber[len(mobileNumber)-2:]
}

func maskMiddleCharacters(input string, prefixLength, suffixLength int) string {
	if len(input) <= prefixLength+suffixLength {
		return input
	}

	prefix := input[:prefixLength]
	suffix := input[len(input)-suffixLength:]
	middle := strings.Repeat("*", len(input)-prefixLength-suffixLength)

	return prefix + middle + suffix
}
