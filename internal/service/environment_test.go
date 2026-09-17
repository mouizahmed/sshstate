package service

import "testing"

func TestEnvironmentPassesOnlyCertificateAndProxySettings(t *testing.T) {
	for _, name := range passedEnvironment {
		t.Setenv(name, "")
	}
	t.Setenv("SSL_CERT_FILE", "/etc/corp/ca.pem")
	t.Setenv("HTTPS_PROXY", "http://proxy.corp:3128")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "never")
	env := Environment()
	if len(env) != 2 || env["SSL_CERT_FILE"] != "/etc/corp/ca.pem" || env["HTTPS_PROXY"] != "http://proxy.corp:3128" {
		t.Fatalf("unexpected environment for the service: %v", env)
	}
}
