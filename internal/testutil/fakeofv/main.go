// Command fakeofv simulates a bounded openfortivpn transcript without networking.
// Tests select a scenario through the validated realm field, never ambient secrets.
package main

import (
	"bufio"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// certificate is a placeholder SHA256 used solely by deterministic rejection tests.
const certificate = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// main reads the helper's fixed argv shape, replays a scenario, and exits nonzero
// on invalid invocation or pinentry failure. It never opens a network connection.
func main() {
	realm, pin, trust := "", "", ""
	config := os.NewFile(3, "account-config")
	if config == nil {
		os.Exit(90)
	}
	scanner := bufio.NewScanner(config)
	username := ""
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			os.Exit(90)
		}
		switch strings.TrimSpace(key) {
		case "realm":
			realm = strings.TrimSpace(value)
		case "username":
			username = strings.TrimSpace(value)
		default:
			os.Exit(90)
		}
	}
	if scanner.Err() != nil || username == "" {
		os.Exit(90)
	}
	_ = config.Close()
	for _, arg := range os.Args[1:] {
		if v, ok := strings.CutPrefix(arg, "--pinentry="); ok {
			pin = v
		}
		if v, ok := strings.CutPrefix(arg, "--trusted-cert="); ok {
			trust = v
		}
	}
	if pin == "" || len(os.Environ()) != 4 || os.Getenv("LANG") != "C" || os.Getenv("PATH") != "/usr/sbin:/usr/bin:/sbin:/bin" {
		os.Exit(90)
	}
	if realm == "ignore-term" {
		signal.Ignore(syscall.SIGTERM)
	}
	if realm == "stall" {
		time.Sleep(30 * time.Second)
		return
	}
	if realm == "early" {
		return
	}
	if value, ok := strings.CutPrefix(realm, "exit-"); ok {
		code, err := strconv.Atoi(value)
		if err != nil || code < 0 || code > 255 {
			os.Exit(90)
		}
		os.Exit(code)
	}
	if realm == "cert" && trust != certificate {
		printLine("ERROR:  Gateway certificate validation failed, and the certificate digest is not in the local whitelist. If you trust it, rerun with:")
		printLine("ERROR:      --trusted-cert " + certificate)
		printLine("ERROR:  Gateway certificate:")
		printLine("ERROR:      subject:")
		printLine("ERROR:          CN=vpn.example.com")
		printLine("ERROR:      issuer:")
		printLine("ERROR:          CN=Example CA")
		printLine("ERROR:      sha256 digest:")
		printLine("ERROR:          " + certificate)
		os.Exit(1)
	}
	if realm == "delayed" {
		time.Sleep(250 * time.Millisecond)
	}
	printLine("INFO:   Connected to gateway.")
	secret, err := ask(pin, "example_password")
	if err != nil {
		os.Exit(91)
	}
	if realm == "roundtrip" && secret != "fixture%password+\r\n\x00" {
		os.Exit(94)
	}
	if realm == "leak" || realm == "roundtrip" {
		printLine("unlabelled " + secret)
		_, _ = fmt.Fprintln(os.Stderr, "password="+secret)
		_, _ = fmt.Fprintln(os.Stderr, "pppd: diagnostic fixture retained")
	}
	if realm == "auth" {
		printLine("ERROR:  Could not authenticate to gateway. Please check the password, client certificate, etc.")
		os.Exit(1)
	}
	if realm == "code" {
		if _, err := ask(pin, "example_otp"); err != nil {
			os.Exit(92)
		}
	}
	printLine("INFO:   Authenticated.")
	printLine("INFO:   Got addresses: [10.20.0.10], ns [10.20.0.1], ns_suffix [corp.example.com]")
	printLine("INFO:   Interface ppp0 is UP.")
	printLine("INFO:   Tunnel is up and running.")
	if realm == "transport" {
		time.Sleep(100 * time.Millisecond)
		printLine("INFO:   Closed connection to gateway.")
		return
	}
	time.Sleep(30 * time.Second)
}

// printLine writes a fixture record and treats a closed output pipe as termination.
func printLine(line string) {
	if _, err := fmt.Fprintln(os.Stdout, line); err != nil {
		os.Exit(93)
	}
}

// ask forks the supplied pinentry with pipes and performs openfortivpn's Assuan
// exchange. Responses are read only in memory; malformed replies fail the fixture.
func ask(path, key string) (string, error) {
	cmd := exec.Command(path)
	cmd.Env = os.Environ()
	input, err := cmd.StdinPipe()
	if err != nil {
		return "", err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		_ = input.Close()
		return "", err
	}
	if err := cmd.Start(); err != nil {
		_ = input.Close()
		return "", err
	}
	defer func() { _ = input.Close(); _ = output.Close(); _ = cmd.Wait() }()
	reader := bufio.NewReader(output)
	expectOK := func() error {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if !strings.HasPrefix(line, "OK") {
			return fmt.Errorf("pinentry refused")
		}
		return nil
	}
	if err := expectOK(); err != nil {
		return "", err
	}
	for _, line := range []string{"SETTITLE VPN", "SETDESC Account credential", "SETKEYINFO " + key, "SETPROMPT Password:", "OPTION ttytype=dumb"} {
		if _, err := io.WriteString(input, line+"\n"); err != nil {
			return "", err
		}
		if err := expectOK(); err != nil {
			return "", err
		}
	}
	if _, err := io.WriteString(input, "GETPIN\n"); err != nil {
		return "", err
	}
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(line, "D ") {
		return "", fmt.Errorf("pinentry cancelled")
	}
	if err := expectOK(); err != nil {
		return "", err
	}
	if _, err := io.WriteString(input, "BYE\n"); err != nil {
		return "", err
	}
	if err := expectOK(); err != nil {
		return "", err
	}
	// Assuan data escapes percent and control bytes but leaves plus literal.
	return url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(line, "D "), "\n"))
}
