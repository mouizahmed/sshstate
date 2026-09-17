package knownhosts

import "testing"

func FuzzParseLine(f *testing.F) {
	f.Add("10.0.0.5 " + sampleKey)
	f.Add("@revoked 10.0.0.5 " + sampleKey)
	f.Add("|1|abc|def " + sampleKey)
	f.Add("*.example.com,!secret.example.com " + sampleKey)
	f.Add("")
	f.Add("# a comment")
	f.Add("[10.0.0.5]:2222 " + sampleKey)

	f.Fuzz(func(t *testing.T, line string) {
		e, err := ParseLine(line)
		if err != nil {
			return
		}
		for _, host := range []string{"", "10.0.0.5", line, "[::1]:22"} {
			_ = e.Matches(host)
		}
		if e.Line == "" {
			t.Fatal("an accepted entry kept no line")
		}
		if LineDigest(e.Line) != LineDigest(e.Line) {
			t.Fatal("the line digest is not stable")
		}
	})
}

func FuzzParseFile(f *testing.F) {
	f.Add("10.0.0.5 " + sampleKey + "\nbroken\n10.0.0.6 " + sampleKey + "\n")
	f.Add("\n\n\n")
	f.Add("# comment only\n")

	f.Fuzz(func(t *testing.T, body string) {
		entries, problems := Parse(body)
		for _, e := range entries {
			if e.LineNo < 1 {
				t.Fatalf("entry reported at line %d", e.LineNo)
			}
		}
		for _, p := range problems {
			if p.LineNo < 1 {
				t.Fatalf("problem reported at line %d", p.LineNo)
			}
		}
	})
}
