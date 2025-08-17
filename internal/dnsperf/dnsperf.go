package dnsperf

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// Run runs dnsperf which read the queries from the io.Reader and benchmarks the server running on addr. The
// test runs for duration. The thread count is set the runtime.NumCPU. I.e.
//
//	Run(q, "127.0.0.1:8053", udp, 2)
//
// runs: "dnsperf -s 127.0.0.1 -p 8053 -l 2 -c 4 -T 4", if runtime.NumCPU returns 4.
//
// See dnsperf on how to create queries. The queries io.Reader is drained in placed in a file.
//
// The output is simular to running Go benchmark tests and can be used in benchstat.
func Run(t *testing.T, queries io.Reader, addr, network string, duration time.Duration) error {
	p, err := io.ReadAll(queries)
	if err != nil {
		return err
	}
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/queries.txt", p, 0600); err != nil {
		return err
	}

	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return err
	}
	args := []string{
		"-s", host,
		"-p", port,
		"-d", dir + "/queries.txt",
		"-l", fmt.Sprintf("%d", int(duration.Seconds())),
		"-c", strconv.Itoa(runtime.NumCPU()), // clients
		"-T", strconv.Itoa(runtime.NumCPU()), // threads
	}
	if network == "tcp" {
		args = append(args, "-m", network)
	}

	cmd := exec.Command("dnsperf", args...)
	cmd.Stdin = queries
	if p, err = cmd.CombinedOutput(); err != nil {
		t.Logf("%s", p)
		return err
	}

	qps, lost := queriesPerSecond(bytes.NewReader(p))
	if qps == 0 {
		return fmt.Errorf("could not determine queries per second")
	}
	if lost > 0 {
		return fmt.Errorf("seen %f lost queries, inconclusive test", lost)
	}
	// fake this a bit:
	// goos: linux
	// goarch: arm64
	// pkg: codeberg.org/miekg/dns
	// BenchmarkMakeMsgQuestionMX
	fmt.Printf(`goos: %s
goarch: %s
pkg: codeberg.org/miekg/dns
%s
`, runtime.GOOS, runtime.GOARCH, name)

	nsPerOp := 1e9 / qps
	fmt.Printf("%s-%d\t%d\t\t\t%.1f ns/op\n", name, runtime.NumCPU(), int(qps), nsPerOp)
	fmt.Println(`PASS
ok      codeberg.org/miekg/dns  2.531s`)
	return nil
}

const name = "BenchmarkDNSPerf"

var (
	qpsregex  = regexp.MustCompile(`Queries per second:\s+([\d.]+)`)
	lostregex = regexp.MustCompile(`Queries lost:\s+([\d.]+)`)
)

func queriesPerSecond(r io.Reader) (qps, lost float64) {
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := scanner.Text()
		if matches := qpsregex.FindStringSubmatch(line); len(matches) > 1 {
			qps, _ = strconv.ParseFloat(matches[1], 64)
		}
		if matches := lostregex.FindStringSubmatch(line); len(matches) > 1 {
			lost, _ = strconv.ParseFloat(matches[1], 64)
		}
	}

	return qps, lost
}
