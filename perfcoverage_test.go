package theca

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"testing"

	"github.com/go-scikit/refbench"
)

// TestPerfAPICoverage is the API-coverage half of bench/'s TestPerf, run in the
// root module's CI without cgo or the C references (bench/ is the cgo module
// and no workflow runs it): every exported function and method of the module
// has a performance case in bench/perf_test.go or a reasoned entry in
// docs/perf-exempt.md, and nothing else is named. refbench.RunCI does the same
// check but needs perf.json and the cases' allocation counts, which need the
// bench module; its pure functions are used here.
func TestPerfAPICoverage(t *testing.T) {
	public, err := refbench.PublicFuncs(".")
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.Open("docs/perf-exempt.md")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	exempt, err := refbench.ParseExempt(f)
	if err != nil {
		t.Fatal(err)
	}
	cov := refbench.CheckCoverage(public, caseFuncs(t), exempt)
	for _, m := range cov.Missing {
		t.Errorf("%s has no performance case and no entry in docs/perf-exempt.md", m)
	}
	for _, m := range cov.Unknown {
		t.Errorf("%s is named by a case or an exemption but is not a public function", m)
	}
	for _, m := range cov.Both {
		t.Errorf("%s has a case and an exemption", m)
	}
}

// caseFuncs returns the Func of every refbench.Case literal in
// bench/perf_test.go, read from the syntax tree because the bench module
// cannot be imported without cgo.
func caseFuncs(t *testing.T) []refbench.Case {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "bench/perf_test.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var cases []refbench.Case
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, e := range lit.Elts {
			kv, ok := e.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Func" {
				if s, ok := kv.Value.(*ast.BasicLit); ok && s.Kind == token.STRING {
					name, err := strconv.Unquote(s.Value)
					if err != nil {
						t.Fatal(err)
					}
					cases = append(cases, refbench.Case{Func: name})
				}
			}
		}
		return true
	})
	if len(cases) == 0 {
		t.Fatal("no refbench case found in bench/perf_test.go")
	}
	return cases
}
