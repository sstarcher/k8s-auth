# Kubernetes Authenticator - DEPRECATED

I recommend the use of [kubelogin](https://github.com/int128/kubelogin).

[![CircleCI](https://circleci.com/gh/sstarcher/k8s-auth.svg?style=shield)](https://circleci.com/gh/sstarcher/k8s-auth)
[![GitHub release](https://img.shields.io/github/release/sstarcher/k8s-auth.svg)](https://github.com/sstarcher/k8s-auth/releases)

Provides out of band OpenID Connect support.  This project has only be tested with [Dex](https://github.com/coreos/dex/)

## Install

Download the binary from the release page

## Usage

* k8s-auth NAME - Authenticates to the provider and writes out the kubernetes config

## Configuration

Create a file `$HOME/.k8s-auth.yaml`

Example for dex deployed at `dex.dev.example.com` with kops as the server located at `api.internal.dev.example.com`
```yaml
dev:
  issuer: https://dex.dev.example.com
  server: https://api.internal.dev.example.com
  insecureSkipTLSVerify: true
```

Multiple configurations can be stored in a single file.

### Credits
The work for this originally started from https://github.com/coreos/dex/tree/master/cmd/example-app
