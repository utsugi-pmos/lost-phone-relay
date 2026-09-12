package main

import "encoding/json"

// The JSON keys were Spanish until 2026-09-11: the relay wrote them into its own
// state file, served them to the panel and accepted them from the phone. Renaming
// them to English would have made the running relay lose its registered phones and
// would have broken every phone that had not been upgraded yet.
//
// So there is one map of old->new and one pass that rewrites incoming JSON before
// it is decoded. It runs on the two doors where foreign JSON arrives -- the state
// file on disk and an HTTP request body -- and nowhere else, so the structs below
// carry only the English names.
//
// This can go once no phone reports with the old keys, which means once every
// phone runs lost-phone 1.2 or newer.
var legacyKeys = map[string]string{
	// Position
	"cuando":            "when",
	"tiene_coordenadas": "has_coordinates",
	"latitud":           "latitude",
	"longitud":          "longitude",
	"precision_metros":  "accuracy_m",
	"origen":            "source",
	"celda":             "cell",
	"bateria":           "battery",
	// Device and the state file
	"nombre":       "name",
	"testigo":      "token",
	"alta":         "added",
	"visto":        "last_seen",
	"pendiente":    "pending",
	"historial":    "history",
	"dispositivos": "devices",
	"pareo":        "pairing",
	// pairing
	"codigo":   "code",
	"caduca":   "expires",
	"intentos": "tries",
	// requests from the panel and the phone
	"orden":     "command",
	"mensaje":   "message",
	"ultima":    "last",
	"conectado": "online",
}

// translateLegacyKeys walks decoded JSON and renames the keys above. A key that is
// already English is left alone, and an old key never wins over a new one: if both
// are present the new one stays.
func translateLegacyKeys(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			out[k] = translateLegacyKeys(val)
		}
		for old, new := range legacyKeys {
			if val, ok := out[old]; ok {
				if _, taken := out[new]; !taken {
					out[new] = val
				}
				delete(out, old)
			}
		}
		return out
	case []any:
		for i := range t {
			t[i] = translateLegacyKeys(t[i])
		}
		return t
	default:
		return v
	}
}

// decodeWithLegacyKeys decodes JSON that may still carry the Spanish keys.
func decodeWithLegacyKeys(data []byte, v any) error {
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	fixed, err := json.Marshal(translateLegacyKeys(raw))
	if err != nil {
		return err
	}
	return json.Unmarshal(fixed, v)
}
