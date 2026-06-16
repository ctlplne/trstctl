package plainpkg

// No //trstctl:keymaterial marker here, so ordinary string usage is fine and
// must not be flagged.

type Config struct {
	Name string
}

func Greet(who string) string { return who }
