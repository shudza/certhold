package peerfiles

// HomeOf returns the conventional home directory path for the given Unix user.
// Constraint: matches /etc/passwd defaults on standard distros (root => /root,
// everything else => /home/<user>). The user-mode install script resolves the
// actual home via `getent passwd` at install time; this helper exists for code
// paths (cli update/group/revoke/rekey) that need to compute the remote push
// path without a live SSH connection to call getent.
func HomeOf(user string) string {
	if user == "root" {
		return "/root"
	}
	return "/home/" + user
}
