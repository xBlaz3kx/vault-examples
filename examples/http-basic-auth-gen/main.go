package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/samber/oops"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, os.Kill, syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	// Load configuration
	config := Configuration{
		Address:                          "http://localhost:8200",
		Token:                            "00000000-0000-0000-0000-000000000000",
		PasswordPolicyGenerationFilePath: "./policy.hcl",
	}
	// Create vault client
	vaultClient, err := NewClient(config)
	if err != nil {
		panic(oops.Wrapf(err, "failed to create vault client"))
	}

	username := "username"

	// Generate basic auth password
	password, err := vaultClient.GenerateBasicAuthCredentials(ctx, username)
	if err != nil {
		slog.ErrorContext(ctx, "failed to generate basic auth credentials", slog.String("error", err.Error()))
		return
	}

	slog.InfoContext(ctx, "generated basic auth credentials", slog.String("username", username), slog.String("password", password))

	// Authenticate
	authenticated, err := vaultClient.Authenticate(ctx, username, password)
	if err != nil {
		slog.ErrorContext(ctx, "failed to authenticate", slog.String("error", err.Error()))
		return
	}

	slog.InfoContext(ctx, "Result?", slog.Bool("authenticated", authenticated))

	// Remove basic auth credentials
	err = vaultClient.RemoveBasicAuthCredentials(ctx, username)
	if err != nil {
		slog.ErrorContext(ctx, "failed to remove basic auth credentials", slog.String("error", err.Error()))
		return
	}

	slog.InfoContext(ctx, "removed basic auth credentials")

	// Authenticate
	authenticated, err = vaultClient.Authenticate(ctx, username, password)
	if err != nil {
		slog.ErrorContext(ctx, "failed to authenticate", slog.String("error", err.Error()))
		return
	}

	slog.InfoContext(ctx, "Result?", slog.Bool("authenticated", authenticated))
}

type Configuration struct {
	Address                          string `yaml:"address" json:"address" mapstructure:"address"`
	Token                            string `yaml:"token" json:"token" mapstructure:"token"`
	PasswordPolicyGenerationFilePath string `yaml:"passwordPolicy" json:"passwordPolicy" mapstructure:"passwordPolicy"`
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

	policy, err := client.getPolicyFromFile(config.PasswordPolicyGenerationFilePath)
	if err != nil {
		return nil, err
	}

	err = client.createOrUpdatePasswordPolicy(policyName, policy)
	if err != nil {
		return nil, err
	}

	return client, nil
}

const policyName = "basicAuth"
const authMountPath = "http/auth"

// getPolicyFromFile retrieves the policy from file
func (vc *Client) getPolicyFromFile(policyPath string) (string, error) {
	file, err := os.ReadFile(policyPath)
	if err != nil {
		return "", err
	}

	return string(file), nil
}

// createOrUpdatePasswordPolicy creates or updates a password policy on Vault.
func (vc *Client) createOrUpdatePasswordPolicy(name, policy string) error {
	// todo verify compatibility
	data := map[string]interface{}{
		"policy": policy,
	}
	_, err := vc.vault.Logical().Write("/sys/policies/password/"+name, data)
	if err != nil {
		return fmt.Errorf("failed to create new policy: %w", err)
	}

	return nil
}

// generatePasswordFromPolicy generates a password based on the provided policy.
// Prerequisite is that the policy already exists.
func (vc *Client) generatePasswordFromPolicy(policy string) (string, error) {
	resp, err := vc.vault.Logical().Read("/sys/policies/password/" + policy + "/generate")
	if err != nil {
		return "", fmt.Errorf("failed to generate new password: %w", err)
	}

	return resp.Data["password"].(string), nil
}

// GenerateBasicAuthCredentials generates a password for an HTTP basic auth client
func (vc *Client) GenerateBasicAuthCredentials(ctx context.Context, username string) (password string, err error) {
	slog.Info("vault.GenerateBasicAuthCredentials", slog.String("username", username))

	password, err = vc.generatePasswordFromPolicy(policyName)
	if err != nil {
		return "", oops.Wrapf(err, "unable to generate password")
	}

	req := map[string]interface{}{
		"password": password,
	}
	_, err = vc.vault.KVv2(authMountPath).Put(ctx, username, req)
	if err != nil {
		return "", oops.Wrapf(err, "failed to write basic auth credentials")
	}

	return password, nil
}

// RemoveBasicAuthCredentials removes the basic auth credentials completely
func (vc *Client) RemoveBasicAuthCredentials(ctx context.Context, username string) error {
	slog.Info("Removing credentials", slog.String("username", username))

	v := vc.vault.KVv2(authMountPath)

	versionList, err := v.GetVersionsAsList(ctx, username)
	if err != nil {
		return oops.Wrapf(err, "failed to list versions for %s", username)
	}

	versions := []int{}
	for _, metadata := range versionList {
		versions = append(versions, metadata.Version)
	}

	return vc.vault.KVv2(authMountPath).Destroy(ctx, username, versions)
}

// Authenticate checks if the passwords for the username are matching
func (vc *Client) Authenticate(ctx context.Context, username, password string) (bool, error) {
	slog.Info("Authenticating client", slog.String("username", username))

	response, err := vc.vault.KVv2(authMountPath).Get(ctx, username)
	if err != nil {
		return false, err
	}

	if response == nil {
		return false, nil
	}

	return response.Data["password"] == password, nil
}
