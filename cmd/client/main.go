package main

import (
	"fmt"

	_ "github.com/jackc/pgx/v5/stdlib"
)

// nolint: gochecknoglobals
var (
	buildVersion string
	buildDate    string
	buildCommit  string
)

func init() {
	if buildVersion == "" {
		buildVersion = "N/A"
	}

	if buildDate == "" {
		buildDate = "N/A"
	}

	if buildCommit == "" {
		buildCommit = "N/A"
	}
}

func main() {
	cmd := Cmd()
	cmd.Version = fmt.Sprintf("%s\nbuild date: %s\nbuild commit: %s", buildVersion, buildDate, buildCommit)

	if err := cmd.Execute(); err != nil {
		panic(err)
	}
}
