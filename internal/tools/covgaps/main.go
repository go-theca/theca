// Command covgaps reads a Go cover profile and prints every uncovered block.
// It exits 1 when there is any, so it doubles as the 100 % coverage gate.
package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

func run(path string, out *os.File) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	var total, missed int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "mode:") {
			continue
		}
		// Dev tools are not part of the library; Go lists untested
		// packages at 0 %, which would fail the gate for no reason.
		if strings.Contains(line, "/internal/tools/") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 3 {
			return 0, fmt.Errorf("malformed profile line %q", line)
		}
		n, err1 := strconv.Atoi(fields[1])
		c, err2 := strconv.Atoi(fields[2])
		if err1 != nil || err2 != nil {
			return 0, fmt.Errorf("malformed profile line %q", line)
		}
		total += n
		if c == 0 {
			missed += n
			fmt.Fprintln(out, "uncovered:", fields[0], "statements:", n)
		}
	}
	fmt.Fprintf(out, "statements: %d, uncovered: %d\n", total, missed)
	return missed, sc.Err()
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: covgaps cover.out")
		os.Exit(2)
	}
	missed, err := run(os.Args[1], os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if missed > 0 {
		os.Exit(1)
	}
}
