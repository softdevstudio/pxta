// Command findbrowser prints the browser PXTA would use, for the recorded
// test environment.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/softdevstudio/pxta"
)

func main() {
	p, err := pxta.FindBrowser("")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	out, _ := exec.Command(p, "--version").Output()
	fmt.Printf("%s (%s)\n", strings.TrimSpace(string(out)), p)
}
