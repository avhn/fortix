package install

import (
	"bytes"
	_ "embed"
	"encoding/xml"
	"errors"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"

	"github.com/avhn/fortix/internal/paths"
)

// linuxUnit embeds the systemd service template. Privilege restrictions retain
// pppd's required capabilities while limiting writable helper-owned locations.
//
//go:embed templates/fortix-helper.service.tmpl
var linuxUnit string

// darwinPlist embeds the system-wide launchd helper definition, not a user agent.
//
//go:embed templates/com.github.avhn.fortix.helper.plist.tmpl
var darwinPlist string

// RenderService renders a launchd plist or systemd unit with validated absolute
// machine paths. XML and systemd escaping prevent path text from adding directives.
// Unsupported platforms, malformed paths and template errors are returned.
func RenderService(platform string, p paths.Paths) (string, error) {
	for _, path := range []string{p.BinaryDir, p.State, p.Logs, p.Profiles, p.ResolverDir} {
		if !cleanPath(path) {
			return "", errors.New("invalid service path")
		}
	}
	content := linuxUnit
	if platform == "darwin" {
		content = darwinPlist
	} else if platform != "linux" {
		return "", errors.New("unsupported service platform")
	}
	funcs := template.FuncMap{"quote": systemdQuote, "xml": xmlText}
	t, err := template.New("service").Funcs(funcs).Parse(content)
	if err != nil {
		return "", err
	}
	data := struct{ Helper, State, Logs, Config, Resolver string }{
		filepath.Join(p.BinaryDir, "fortix-helper"), p.State, p.Logs, filepath.Dir(p.Profiles), p.ResolverDir,
	}
	var out bytes.Buffer
	if err := t.Execute(&out, data); err != nil {
		return "", err
	}
	return out.String(), nil
}

// systemdQuote escapes a path as one quoted systemd argument and doubles percent
// specifiers and dollar signs so file names cannot trigger manager expansion.
func systemdQuote(path string) string {
	return strconv.Quote(strings.ReplaceAll(strings.ReplaceAll(path, "%", "%%"), "$", "$$"))
}

// xmlText encodes path text for a plist string element and returns XML errors.
func xmlText(path string) (string, error) {
	var out bytes.Buffer
	err := xml.EscapeText(&out, []byte(path))
	return out.String(), err
}
