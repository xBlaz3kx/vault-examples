package main

import (
	"context"
	"log/slog"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
	"github.com/samber/oops"
)

func main() {

}

type Configuration struct {
	Address string `yaml:"address" json:"address" mapstructure:"address"`
	Token   string `yaml:"token" json:"token" mapstructure:"token"`
}

type Certificate struct {
	Certificate    string     `mapstructure:"certificate"`
	IssuingCA      string     `mapstructure:"issuing_ca"`
	CAChain        []string   `mapstructure:"ca_chain"`
	PrivateKey     string     `mapstructure:"private_key"`
	PrivateKeyType string     `mapstructure:"private_key_type"`
	SerialNumber   string     `mapstructure:"serial_number"`
	Expiry         *time.Time `mapstructure:"expiry"`
}

type Client struct {
	vault *vault.Client
}

func NewClient(config Configuration) (*Client, error) {
	cfg := vault.DefaultConfig()
	cfg.Address = config.Address
	cfg.MaxRetries = 3
	cfg.MaxRetryWait = 30 * time.Second
	cfg.MaxRetryWait = 30 * time.Second

	vaultApiClient, err := vault.NewClient(cfg)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create vault client")
	}

	vaultApiClient.SetToken(config.Token)

	client := &Client{
		vault: vaultApiClient,
	}

	return client, nil
}

// IssueCertificate creates a new certificate
func (vc *Client) IssueCertificate(ctx context.Context, userId string) (*Certificate, error) {
	slog.Info("Issuing a certificate", slog.String("userId", userId))

	req := map[string]interface{}{
		"private_key_format": "pem",
		"common_name":        userId,
		"user_ids":           userId,
	}
	secret, err := vc.vault.Logical().WriteWithContext(ctx, "/pki/issue/mtls", req)
	if err != nil {
		return nil, oops.Wrapf(err, "failed to create a certificate")
	}

	var cert Certificate
	if err := mapstructure.Decode(secret.Data, &cert); err != nil {
		return nil, oops.Wrapf(err, "failed to decode the certificate")
	}

	return &cert, nil
}

// RevokeCertificate revokes a certificate by serial number
func (vc *Client) RevokeCertificate(ctx context.Context, serialNumber string) error {
	slog.Info("Revoking a certificate", slog.String("serialNumber", serialNumber))

	req := map[string]interface{}{
		"serial_number": serialNumber,
	}
	_, err := vc.vault.Logical().WriteWithContext(ctx, "/pki/revoke", req)
	if err != nil {
		return oops.Wrapf(err, "failed to revoke certificate")
	}

	return nil
}
