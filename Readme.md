# Vault examples

This repository contains example use cases with HashiCorp Vault, implemented in Go with the
[API client](https://github.com/hashicorp/vault/tree/main/api).

## Prerequisites

- Docker with Docker compose installed
- Go version 1.23.0

### Running the examples

1. Make sure that Vault is up and running before executing the example:

    ```bash
    docker compose up -d 
    ```

2. Run your example:

    ```bash
      cd examples/http-basic-auth-gen/ && go run .
    ```

## Licence

Check out the [licence](LICENCE.md).

## Contributing

Contributions are welcome! Please refer to [contribution guidelines](CONTRIBUTING.md).
Let me know if there are any use cases you would like to be covered!