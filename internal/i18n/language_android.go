package i18n

import "artb/internal/androidprop"

func systemTag() string {
	for _, key := range []string{"persist.sys.locale", "persist.sys.locales", "ro.product.locale"} {
		if tag := androidprop.Get(key); tag != "" {
			return tag
		}
	}
	return ""
}
