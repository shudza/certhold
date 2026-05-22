package cli

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strconv"
	"strings"
)

type ifaceCandidate struct {
	Name string
	IP   net.IP
}

var skipIfaceRe = regexp.MustCompile(`^(docker|br-|veth|virbr|tun|tap|cni)`)

var listInterfaces = func() ([]ifaceCandidate, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []ifaceCandidate
	for _, ifa := range ifs {
		if ifa.Flags&net.FlagLoopback != 0 {
			continue
		}
		if ifa.Flags&net.FlagUp == 0 {
			continue
		}
		if skipIfaceRe.MatchString(ifa.Name) {
			continue
		}
		addrs, err := ifa.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			if ip4.IsLinkLocalUnicast() {
				continue
			}
			out = append(out, ifaceCandidate{Name: ifa.Name, IP: ip4})
		}
	}
	return out, nil
}

func selectInterface(listenIP string, noPrompt bool, in io.Reader, out io.Writer) (ifaceCandidate, error) {
	if listenIP != "" {
		ip := net.ParseIP(listenIP)
		if ip == nil {
			return ifaceCandidate{}, fmt.Errorf("invalid --listen-ip %q", listenIP)
		}
		ip4 := ip.To4()
		if ip4 == nil {
			return ifaceCandidate{}, fmt.Errorf("--listen-ip %q is not IPv4", listenIP)
		}
		return ifaceCandidate{Name: "", IP: ip4}, nil
	}

	cands, err := listInterfaces()
	if err != nil {
		return ifaceCandidate{}, fmt.Errorf("list interfaces: %w", err)
	}
	if len(cands) == 0 {
		return ifaceCandidate{}, errors.New("no usable network interfaces found")
	}
	if len(cands) == 1 {
		return cands[0], nil
	}
	if noPrompt {
		var ips []string
		for _, c := range cands {
			ips = append(ips, c.IP.String())
		}
		return ifaceCandidate{}, fmt.Errorf("multiple candidates found, pass --listen-ip to choose: %s", strings.Join(ips, ", "))
	}

	reader := bufio.NewReader(in)
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Fprintln(out, "Detected network interfaces:")
		for i, c := range cands {
			fmt.Fprintf(out, "  [%d] %-8s %s\n", i+1, c.Name, c.IP.String())
		}
		fmt.Fprintf(out, "\nWhich interface should peers reach certhold on? [1-%d]: ", len(cands))

		line, err := reader.ReadString('\n')
		if err != nil {
			if errors.Is(err, io.EOF) && strings.TrimSpace(line) == "" {
				return ifaceCandidate{}, errors.New("init aborted")
			}
			if !errors.Is(err, io.EOF) {
				return ifaceCandidate{}, fmt.Errorf("read input: %w", err)
			}
		}
		s := strings.TrimSpace(line)
		if s == "q" || s == "Q" {
			return ifaceCandidate{}, errors.New("init aborted")
		}
		n, perr := strconv.Atoi(s)
		if perr == nil && n >= 1 && n <= len(cands) {
			return cands[n-1], nil
		}
		fmt.Fprintf(out, "Invalid selection %q.\n", s)
		if errors.Is(err, io.EOF) {
			return ifaceCandidate{}, errors.New("init aborted")
		}
	}
	return ifaceCandidate{}, errors.New("too many invalid attempts; init aborted")
}
