package control

import (
	"fmt"
	"github.com/securock/securock/internal/identity"
)

func validateState(s State) error {
	subjects := map[string]bool{}
	for id, t := range s.Tenants {
		if !identity.ValidID(id) || t == nil || t.Members == nil || t.Projects == nil || t.Jobs == nil {
			return fmt.Errorf("invalid tenant state")
		}
		for subject, m := range t.Members {
			if m.Subject != subject || subject == "" || subjects[subject] || !identity.ValidID(m.ID) {
				return fmt.Errorf("invalid member state")
			}
			subjects[subject] = true
		}
		for id, p := range t.Projects {
			if id != p.ID || !identity.ValidID(id) {
				return fmt.Errorf("invalid project state")
			}
		}
		for id, j := range t.Jobs {
			if id != j.ID || !identity.ValidID(id) {
				return fmt.Errorf("invalid job state")
			}
			if _, ok := t.Projects[j.Project]; !ok {
				return fmt.Errorf("orphaned job")
			}
		}
	}
	return nil
}
