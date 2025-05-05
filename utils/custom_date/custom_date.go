package custom_date

import (
	"encoding/json"
	"fmt"
	"time"
)

type CustomDate struct {
	time.Time
}

const customDateLayout = "2006-01-02"

func (cd *CustomDate) UnmarshalJSON(b []byte) error {
	s := string(b)
	s = s[1 : len(s)-1] // Remove the surrounding quotes

	t, err := time.Parse(customDateLayout, s)
	if err != nil {
		return fmt.Errorf("invalid date format: %v", err)
	}

	cd.Time = t
	return nil
}

func (cd CustomDate) MarshalJSON() ([]byte, error) {
	return json.Marshal(cd.Format(customDateLayout))
}
