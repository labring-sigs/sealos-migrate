package main

import (
	"net/url"
	"testing"
)

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
