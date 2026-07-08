package peerfiles

import "fmt"

// ValidateDialAddress vets a peer dial address before it is stored. Addresses
// are rendered verbatim as `HostName <addr>` lines in ssh_config blocks pushed
// fleet-wide, so a space breaks the directive for every receiving peer and a
// newline injects arbitrary ssh_config directives, and an unbalanced quote
// (single or double) is config-fatal for every ssh invocation by that user.
// Only the character set and length are restricted: any printable ASCII except
// whitespace and quotes, at most 255 bytes. Plain hostnames, IPv4/IPv6
// literals and host:port forms all pass. The empty string is valid — it means
// "clear the address" (dial by peer name).
func ValidateDialAddress(addr string) error {
	if addr == "" {
		return nil
	}
	if len(addr) > 255 {
		return fmt.Errorf("invalid dial address: %d bytes long (max 255)", len(addr))
	}
	for i := 0; i < len(addr); i++ {
		switch c := addr[i]; {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			return fmt.Errorf("invalid dial address %q: contains whitespace", addr)
		case c < 0x21 || c > 0x7e:
			return fmt.Errorf("invalid dial address %q: contains control, non-printable or non-ASCII characters", addr)
		case c == '"' || c == '\'':
			return fmt.Errorf("invalid dial address %q: contains a quote character", addr)
		}
	}
	return nil
}
