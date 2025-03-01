// nolint:revive
package helpers

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func SetupDB(ctx context.Context, t *testing.T, migrationsDir string, scripts ...string) *sqlx.DB {
	t.Helper()

	container, err := postgres.Run(ctx,
		"postgres:17-alpine",
		postgres.WithDatabase("test-db"),
		postgres.WithUsername("postgres"),
		postgres.WithPassword("postgres"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).WithStartupTimeout(5*time.Second)), // nolint:mnd
	)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, container.Terminate(ctx)) })

	conn, err := container.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db := sqlx.MustOpen("pgx", conn)

	t.Cleanup(func() { require.NoError(t, db.Close()) })

	m, err := migrate.New(
		"file://"+migrationsDir,
		strings.Replace(conn, "postgres", "pgx5", 1),
	)
	require.NoError(t, err)

	require.NoError(t, m.Up())
	t.Cleanup(func() { require.NoError(t, m.Down()) })

	for _, script := range scripts {
		if !filepath.IsAbs(script) && !strings.Contains(script, "testdata") {
			script = filepath.Join("testdata", script)
		}

		fd, err := os.Open(script)
		require.NoError(t, err)
		defer fd.Close()

		data, err := io.ReadAll(fd)
		require.NoError(t, err)

		_, err = db.ExecContext(ctx, string(data))
		require.NoError(t, err)
	}

	return db
}
