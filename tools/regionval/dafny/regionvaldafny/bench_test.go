package regionvaldafny

import "testing"

func BenchmarkValidateSite(b *testing.B) {
	w := siteWindow()
	for i := 0; i < b.N; i++ {
		Validate(w, SiteSpec(floor))
	}
}
