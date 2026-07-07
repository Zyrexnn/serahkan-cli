package doctor

import "testing"

func TestDoctorCheckResultType(t *testing.T) {
	_ = CheckResult{
		Name: "test",
	}
}
