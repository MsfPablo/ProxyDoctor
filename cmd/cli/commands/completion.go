package commands

import (
	"sort"
	"strings"

	"github.com/francomano/proxydoctor/core/check"
	checkspkg "github.com/francomano/proxydoctor/core/checks"
	"github.com/francomano/proxydoctor/core/engine"
	"github.com/spf13/cobra"
)

// Shell completion support (#22). Cobra already ships a `completion` command
// that emits bash/zsh/fish/powershell scripts, and those scripts complete flag
// *names* and subcommands out of the box. What they cannot do is suggest
// *values* for flags whose accepted set is dynamic or domain-specific — a user
// typing `proxydoctor diagnose --checks <Tab>` would get file completion before
// this change. RegisterFlagCompletionFunc wires the generated scripts to the
// helpers below so the shell offers the real check IDs, categories, export
// formats, and proxy types instead.

// completeCheckFilters completes the --checks flag with the IDs and categories
// of the default-registered checks plus the literal "all". A diagnosis can load
// extra checks via --plugins, but those are opt-in; the default set is the
// common case and the right thing to offer a user tabbing through a fresh
// invocation.
func completeCheckFilters(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	registry := engine.NewCheckRegistry()
	if err := checkspkg.RegisterDefaults(registry); err != nil {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}

	seen := make(map[string]struct{})
	for id, checker := range registry.ListChecks() {
		seen[id] = struct{}{}
		if cat := string(checker.Category()); cat != "" {
			seen[cat] = struct{}{}
		}
	}
	seen["all"] = struct{}{}

	candidates := make([]string, 0, len(seen))
	for v := range seen {
		candidates = append(candidates, v)
	}
	sort.Strings(candidates)

	// --checks is comma-separated: only complete the segment the cursor is on.
	if i := strings.LastIndex(toComplete, ","); i >= 0 {
		prefix := toComplete[:i+1]
		segment := toComplete[i+1:]
		var matched []string
		for _, c := range candidates {
			if strings.HasPrefix(c, segment) {
				matched = append(matched, prefix+c)
			}
		}
		return matched, cobra.ShellCompDirectiveNoFileComp
	}

	var matched []string
	for _, c := range candidates {
		if strings.HasPrefix(c, toComplete) {
			matched = append(matched, c)
		}
	}
	return matched, cobra.ShellCompDirectiveNoFileComp
}

// completeExportFormat completes --export with the four supported formats.
func completeExportFormat(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	formats := []string{"text", "json", "html", "markdown"}
	var matched []string
	for _, f := range formats {
		if strings.HasPrefix(f, toComplete) {
			matched = append(matched, f)
		}
	}
	return matched, cobra.ShellCompDirectiveNoFileComp
}

// completeProxyType completes --proxy-type with the values ParseProxyConfig
// accepts (see cmd/cli/commands/plugins.go).
func completeProxyType(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	types := []string{"auto", "http", "https", "socks4", "socks5"}
	var matched []string
	for _, t := range types {
		if strings.HasPrefix(t, toComplete) {
			matched = append(matched, t)
		}
	}
	return matched, cobra.ShellCompDirectiveNoFileComp
}

// init wires the helpers into cobra via OnInitialize rather than a plain init()
// because Go runs package init()s in filename order — completion.go runs before
// diagnose.go and plugins.go, so the "checks"/"export"/"proxy-type" flags do not
// exist yet and RegisterFlagCompletionFunc would reject them with "flag does not
// exist". OnInitialize defers the calls to Execute time, after every init() has
// run and the flags are defined.
func init() {
	cobra.OnInitialize(registerCompletionFuncs)
}

func registerCompletionFuncs() {
	diagnoseCmd.RegisterFlagCompletionFunc("checks", completeCheckFilters)
	diagnoseCmd.RegisterFlagCompletionFunc("export", completeExportFormat)
	RootCmd.RegisterFlagCompletionFunc("proxy-type", completeProxyType)
}

// compile-time assertion that the helpers satisfy cobra's signature.
var _ cobra.CompletionFunc = completeCheckFilters
var _ cobra.CompletionFunc = completeExportFormat
var _ cobra.CompletionFunc = completeProxyType

// reference the check package so a future rename of the import set above does
// not silently strand the CompletionFunc assertions.
var _ = check.StatusPassed