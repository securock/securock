package control

import (
	"encoding/json"
	"net/http"
)

func jsonResponse(w http.ResponseWriter, v any) error { return json.NewEncoder(w).Encode(v) }
