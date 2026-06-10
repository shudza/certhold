package clientcli

import _ "embed"

//go:embed certhold-cli
var Script []byte

const Version = "1"
