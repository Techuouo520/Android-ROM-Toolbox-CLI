package androidprop

// #include <stdint.h>
// #include <stdlib.h>
// #include <string.h>
// #include <sys/system_properties.h>
// static void artb_property_value(void *cookie, const char *name, const char *value, uint32_t serial) { (void)name; (void)serial; *(char **)cookie = strdup(value); }
// static char *artb_property(const char *key) { const prop_info *info = __system_property_find(key); char *value = NULL; if (info) __system_property_read_callback(info, artb_property_value, &value); return value; }
import "C"

import (
	"strings"
	"unsafe"
)

// Get returns the trimmed property value, or "" when it is unset; the read callback also covers ro.* values longer than PROP_VALUE_MAX, and skipping a getprop fork saves about 40 ms per call on slow devices.
func Get(key string) string {
	name := C.CString(key)
	defer C.free(unsafe.Pointer(name))
	value := C.artb_property(name)
	if value == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(value))
	return strings.TrimSpace(C.GoString(value))
}
