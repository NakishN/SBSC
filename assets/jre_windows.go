//go:build windows

package assets

import _ "embed"

// JREZip is a portable Temurin JRE 8 for Windows. It is extracted to
// %LOCALAPPDATA%\SBSC on first use, so the scanner works without a
// system-wide Java installation.
//
//go:embed tools/jre8-win64.zip
var JREZip []byte
