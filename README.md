# Encargon

Encargon allows to encrypt and decrypt files using a password.
It protects the bad security of your password using the **Argon2** Key derivation function.
It uses AES CTR 256 to encrypt and decrypt the files.

**Status**: In development

## Development

### Setup using VSCode and Docker

That should be easier and better than a local setup

1. Install [Docker](https://docs.docker.com/install/)
    - On Windows, share a drive with Docker Desktop and have the project on that partition
    - On OSX, share your project directory with Docker Desktop
1. With [Visual Studio Code](https://code.visualstudio.com/download), install the [remote containers extension](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers)
1. In Visual Studio Code, press on `F1` and select `Remote-Containers: Open Folder in Container...`
1. Your dev environment is ready to go!... and it's running in a container :+1:

### Local setup

1. Install [Docker](https://www.docker.com/products/docker-desktop)
1. Install [Go](https://golang.org/dl/)
1. Install [Git](https://git-scm.com/downloads)
1. Download the dependencies

    ```sh
    go mod download
    ```

1. Install [golangci-lint](https://github.com/golangci/golangci-lint#install)

### Guidelines

- Try not to use any third party dependency (except for terminal UI and Wails). As this is a security tool, let's try to keep it to Go standard library.

## TODOs

- [ ] Business logic in Go
- [ ] CLI operation
- [ ] Github workflow to release and build binaries for all platforms
- [ ] Terminal GUI operation
- [ ] UI using [Wails](https://github.com/wailsapp/wails)
