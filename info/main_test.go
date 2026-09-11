package main

import (
	"net/url"
	"testing"
)

func TestParseGlobalDatabaseType(t *testing.T) {
	content := `global:
  featureGates:
    gpuEnabled: false
  database:
    type: postgresql
    provider: polardb-pg
`

	if got := parseGlobalDatabaseType(content); got != databaseTypePostgreSQL {
		t.Fatalf("parseGlobalDatabaseType() = %q, want %q", got, databaseTypePostgreSQL)
	}
}

func TestParseGlobalDatabaseTypeMissing(t *testing.T) {
	content := `global:
  database:
    provider: polardb-pg
`

	if got := parseGlobalDatabaseType(content); got != "" {
		t.Fatalf("parseGlobalDatabaseType() = %q, want empty", got)
	}
}

func TestNormalizeDatabaseType(t *testing.T) {
	tests := map[string]string{
		"postgresql":  databaseTypePostgreSQL,
		"Postgres":    databaseTypePostgreSQL,
		"polardb-pg":  databaseTypePostgreSQL,
		"cockroachdb": databaseTypeCockroach,
		"Cockroach":   databaseTypeCockroach,
		"unknown":     "",
	}
	for input, want := range tests {
		t.Run(input, func(t *testing.T) {
			if got := normalizeDatabaseType(input); got != want {
				t.Fatalf("normalizeDatabaseType(%q) = %q, want %q", input, got, want)
			}
		})
	}
}

func TestSelectPodDatabaseTypePreservesCockroachFallback(t *testing.T) {
	tests := map[string]string{
		"postgresql":  databaseTypePostgreSQL,
		"cockroachdb": databaseTypeCockroach,
		"":            databaseTypeCockroach,
		"unknown":     databaseTypeCockroach,
	}
	for configuredType, want := range tests {
		t.Run(configuredType, func(t *testing.T) {
			if got := selectPodDatabaseType(configuredType); got != want {
				t.Fatalf("selectPodDatabaseType(%q) = %q, want %q", configuredType, got, want)
			}
		})
	}
}

func TestOfflineCenterURL(t *testing.T) {
	const domain = "cloud.example.com"
	const want = "http://offline.cloud.example.com"

	if got := offlineCenterURL(domain); got != want {
		t.Fatalf("offlineCenterURL(%q) = %q, want %q", domain, got, want)
	}
}

func TestResolveLookupUserDBURIUsesPodQueryForKubernetesService(t *testing.T) {
	dbURI := "postgresql://sealos:password@sealos-cockroachdb-public.sealos.svc:26257/global"

	resolvedURI, useDirectQuery, err := resolveLookupUserDBURI(dbURI)
	if err != nil {
		t.Fatalf("resolveLookupUserDBURI returned error: %v", err)
	}
	if useDirectQuery {
		t.Fatalf("expected Kubernetes service URI to use pod query")
	}
	if resolvedURI != dbURI {
		t.Fatalf("expected URI to stay unchanged, got %q", resolvedURI)
	}
}

func TestResolveLookupUserDBURIUsesDirectQueryForExternalURI(t *testing.T) {
	dbURI := "postgresql://sealos:password@db.example.com:26257/global"

	resolvedURI, useDirectQuery, err := resolveLookupUserDBURI(dbURI)
	if err != nil {
		t.Fatalf("resolveLookupUserDBURI returned error: %v", err)
	}
	if !useDirectQuery {
		t.Fatalf("expected external URI to use direct query")
	}

	parsed, err := url.Parse(resolvedURI)
	if err != nil {
		t.Fatalf("failed to parse resolved URI: %v", err)
	}
	if parsed.Query().Get("sslmode") != "disable" {
		t.Fatalf("expected sslmode=disable, got %q", parsed.RawQuery)
	}
}

func TestResolveLookupUserDBURIKeepsExplicitSSLMode(t *testing.T) {
	dbURI := "postgresql://sealos:password@db.example.com:26257/global?sslmode=require"

	resolvedURI, useDirectQuery, err := resolveLookupUserDBURI(dbURI)
	if err != nil {
		t.Fatalf("resolveLookupUserDBURI returned error: %v", err)
	}
	if !useDirectQuery {
		t.Fatalf("expected external URI to use direct query")
	}

	parsed, err := url.Parse(resolvedURI)
	if err != nil {
		t.Fatalf("failed to parse resolved URI: %v", err)
	}
	if parsed.Query().Get("sslmode") != "require" {
		t.Fatalf("expected explicit sslmode to be preserved, got %q", parsed.RawQuery)
	}
}

func TestParseKubernetesServiceRef(t *testing.T) {
	dbURI := "postgresql://postgres:password@sealos-polardb-pg-postgresql-postgresql.sealos.svc:5432/global"

	serviceName, namespace, err := parseKubernetesServiceRef(dbURI)
	if err != nil {
		t.Fatalf("parseKubernetesServiceRef returned error: %v", err)
	}
	if serviceName != "sealos-polardb-pg-postgresql-postgresql" {
		t.Fatalf("serviceName = %q", serviceName)
	}
	if namespace != "sealos" {
		t.Fatalf("namespace = %q", namespace)
	}
}

func TestParseKubernetesServiceRefRejectsExternalHost(t *testing.T) {
	_, _, err := parseKubernetesServiceRef("postgresql://postgres:password@db.example.com:5432/global")
	if err == nil {
		t.Fatal("expected external host to be rejected")
	}
}

func TestRewritePostgreSQLURLForLocalhost(t *testing.T) {
	dbURI := "postgresql://postgres:password@postgresql.sealos.svc:5432/global?sslmode=require"

	got, err := rewritePostgreSQLURLForLocalhost(dbURI)
	if err != nil {
		t.Fatalf("rewritePostgreSQLURLForLocalhost returned error: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("failed to parse rewritten URI: %v", err)
	}
	if parsed.Host != "localhost:5432" {
		t.Fatalf("host = %q, want localhost:5432", parsed.Host)
	}
	if parsed.Query().Get("sslmode") != "disable" {
		t.Fatalf("sslmode = %q, want disable", parsed.Query().Get("sslmode"))
	}
}

func TestRewriteCockroachURLForLocalhostPreservesLegacyDefaults(t *testing.T) {
	dbURI := "postgresql://root:password@cockroachdb.sealos.svc:26257/global"

	got, err := rewriteCockroachURLForLocalhost(dbURI)
	if err != nil {
		t.Fatalf("rewriteCockroachURLForLocalhost returned error: %v", err)
	}
	parsed, err := url.Parse(got)
	if err != nil {
		t.Fatalf("failed to parse rewritten URI: %v", err)
	}
	if parsed.Host != "localhost:26257" {
		t.Fatalf("host = %q, want localhost:26257", parsed.Host)
	}
	if parsed.Query().Get("sslmode") != "verify-full" {
		t.Fatalf("sslmode = %q, want verify-full", parsed.Query().Get("sslmode"))
	}
}
