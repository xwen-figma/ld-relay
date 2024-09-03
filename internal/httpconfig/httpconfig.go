// Package httpconfig provides helpers for special types of HTTP client configuration supported by Relay.
package httpconfig

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/launchdarkly/ld-relay/v8/internal/credential"

	"github.com/launchdarkly/ld-relay/v8/config"

	"github.com/launchdarkly/go-sdk-common/v3/ldlog"
	"github.com/launchdarkly/go-server-sdk/v7/ldcomponents"
	"github.com/launchdarkly/go-server-sdk/v7/ldhttp"
	"github.com/launchdarkly/go-server-sdk/v7/ldntlm"
	"github.com/launchdarkly/go-server-sdk/v7/subsystems"
)

var (
	errNTLMProxyAuthWithoutCredentials = errors.New("NTLM proxy authentication requires username and password")
	errProxyAuthWithoutProxyURL        = errors.New("cannot specify proxy authentication without a proxy URL")
)

// HTTPConfig encapsulates ProxyConfig plus any other HTTP options we may support in the future (currently none).
type HTTPConfig struct {
	config.ProxyConfig
	SDKHTTPConfigFactory *ldcomponents.HTTPConfigurationBuilder
	SDKHTTPConfig        subsystems.HTTPConfiguration
}

// NewHTTPConfig validates all of the HTTP-related options and returns an HTTPConfig if successful.
func NewHTTPConfig(proxyConfig config.ProxyConfig, authKey credential.SDKCredential, userAgent string, loggers ldlog.Loggers) (HTTPConfig, error) {
	configBuilder := ldcomponents.HTTPConfiguration()
	configBuilder.UserAgent(userAgent)

	ret := HTTPConfig{ProxyConfig: proxyConfig}

	// This requires go SDK changes first to support custom TLS config
	configBuilder.CustomPeerCertificateVerification(customVerifyPeerCertificate)

	authKeyStr := ""
	if authKey != nil {
		authKeyStr = authKey.GetAuthorizationHeaderValue()
	}

	if !proxyConfig.URL.IsDefined() && proxyConfig.NTLMAuth {
		return ret, errProxyAuthWithoutProxyURL
	}
	if proxyConfig.URL.IsDefined() {
		loggers.Infof("Using proxy server at %s", proxyConfig.URL.Get().Redacted())
	}

	caCertFiles := proxyConfig.CACertFiles.Values()

	if proxyConfig.NTLMAuth {
		if proxyConfig.User == "" || proxyConfig.Password == "" {
			return ret, errNTLMProxyAuthWithoutCredentials
		}
		transportOpts := []ldhttp.TransportOption{
			ldhttp.ConnectTimeoutOption(ldcomponents.DefaultConnectTimeout),
		}
		for _, filePath := range caCertFiles {
			if filePath != "" {
				transportOpts = append(transportOpts, ldhttp.CACertFileOption(filePath))
			}
		}
		factory, err := ldntlm.NewNTLMProxyHTTPClientFactory(proxyConfig.URL.String(),
			proxyConfig.User, proxyConfig.Password, proxyConfig.Domain, transportOpts...)
		if err != nil {
			return ret, err
		}
		configBuilder.HTTPClientFactory(factory)
		loggers.Info("NTLM proxy authentication enabled")
	} else {
		if proxyConfig.URL.IsDefined() {
			configBuilder.ProxyURL(proxyConfig.URL.String())
		}
		for _, filePath := range caCertFiles {
			if filePath != "" {
				configBuilder.CACertFile(filePath)
			}
		}
	}

	var err error
	ret.SDKHTTPConfigFactory = configBuilder
	ret.SDKHTTPConfig, err = configBuilder.Build(subsystems.BasicClientContext{SDKKey: authKeyStr})
	return ret, err
}

func customVerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	cert, err := x509.ParseCertificate(rawCerts[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %v", err)
	}

	actualHost := cert.Subject.CommonName
	verifyHost := determineVerifyHost(actualHost)

	opts := x509.VerifyOptions{
		DNSName: verifyHost,
		Roots:   nil, // Use system root CA store
	}

	_, err = cert.Verify(opts)
	if err != nil {
		return fmt.Errorf("certificate verification failed for %s (verifying as %s): %v", actualHost, verifyHost, err)
	}

	return nil
}

func determineVerifyHost(actualHost string) string {
	// If the actual host is an AWS VPC endpoint, we should use the original server name for the TLS.
	// Currently the LD PrivateLink only supports the events service.
	if strings.HasSuffix(actualHost, ".vpce.amazonaws.com") {
		return "events.launchdarkly.com"
	}
	return actualHost
}

// Client creates a new HTTP client instance that isn't for SDK use.
func (c HTTPConfig) Client() *http.Client {
	return c.SDKHTTPConfig.CreateHTTPClient()
}
