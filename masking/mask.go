package masking

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
	"time"
)

type SetMaskSensitive struct {
	veryHigh []string // Password
	High     []string // MobileNO
	Medium   []string // Email
	Low      []string // username
}

func NewMaskSensitive(levels ...SetMaskSensitive) *MaskSensitive {
	if len(levels) != 0 {
		var maskLevelVeryHigh []string
		var maskLevelHigh []string
		var maskLevelMedium []string
		var maskLevelLow []string
		for i := 0; i < len(levels); i++ {
			level := levels[i]
			level.veryHigh = append(level.veryHigh, "Password")
			level.High = append(level.High, "mobileNO", "phone")
			level.Medium = append(level.Medium, "Email")
			level.Low = append(level.Low, "username")

			maskLevelVeryHigh = append(maskLevelVeryHigh, level.veryHigh...)
			maskLevelHigh = append(maskLevelHigh, level.High...)
			maskLevelMedium = append(maskLevelMedium, level.Medium...)
			maskLevelLow = append(maskLevelLow, level.Low...)

		}

		return &MaskSensitive{
			maskLevelVeryHigh: maskLevelVeryHigh,
			maskLevelHigh:     maskLevelHigh,
			maskLevelMedium:   maskLevelMedium,
			maskLevelLow:      maskLevelLow,
		}
	}

	var level SetMaskSensitive
	level.veryHigh = append(level.veryHigh, "Password")
	level.High = append(level.High, "mobileNO", "phone")
	level.Medium = append(level.Medium, "Email")
	level.Low = append(level.Low, "username", "name")

	return &MaskSensitive{
		maskLevelVeryHigh: level.veryHigh,
		maskLevelHigh:     level.High,
		maskLevelMedium:   level.Medium,
		maskLevelLow:      level.Low,
	}
}

type MaskSensitive struct {
	maskLevelVeryHigh []string
	maskLevelHigh     []string
	maskLevelMedium   []string
	maskLevelLow      []string
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

	// Handle ptrs
	if val.Kind() == reflect.Ptr {
		return m.MaskSensitiveData(val.Elem().Interface())
	}

	// Unsupported type, return as-is
	return data
}

func (m *MaskSensitive) checkFieldSensitive(fieldName string, fieldValue any) any {
	if contains(m.maskLevelVeryHigh, fieldName) {
		fieldValue = maskPassword(fieldValue.(string))
	} else if contains(m.maskLevelHigh, fieldName) {
		fieldValue = MaskMobileNO(fieldValue.(string), "X")
	} else if contains(m.maskLevelMedium, fieldName) {
		fieldValue = maskValue(fieldValue)
	} else if contains(m.maskLevelLow, fieldName) {
		fieldValue = maskMiddleCharacters(fieldValue.(string), 1, 1)
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
	return "********"
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
