# jc2aws

This is a stipped version of [saml2aws](https://github.com/Versent/saml2aws).

This needs [libfido2](https://github.com/Yubico/libfido2) as a prerequisite.

## Changes

* Support FIDO2/WebAuthn on Linux

  See https://github.com/Versent/saml2aws/pull/592 for the context. jc2aws
  instead uses libfido2, which can be installed with hidraw support.

* WebAuthn over SSH

  This implements an ssh-agent daemon that reacts to a custom extension for
  WebAuthn. By running jc2aws on the SSH client side, the SSH server side can
  access the SSH client side's hardware authenticator.

## Usage

Install with go install:

```bash
go install github.com/draftcode/jc2aws/cmd/jc2aws@latest
```

Running against a local authenticator:

```bash
jc2aws --email yourname@example.com --mfa webauthn --profile_name myawsprofile
```

Running against a remote authenticator:

```bash
[client]$ eval $(jc2aws --start_webauthn_ssh_agent)
[client]$ ssh -A yourserver
[server]$ jc2aws --email yourname@example.com --mfa webauthn --profile_name myawsprofile
```

## WebAuthn over SSH agent protocol

As you can see in the
[Agent](https://pkg.go.dev/golang.org/x/crypto/ssh/agent#ExtendedAgent)
definition of the SSH Agent Golang library, SSH agent protocol has an ability to
send an arbitary byte array. This means that we can implement an arbitrary
request-response protocol that goes through SSH. The SSH agent on the client
side is an RPC server, and this RPC server is exposed to the SSH destination
almost automatically. The SSH destination can call this RPC via `SSH_AUTH_SOCK`.

By using this mechanism, jc2aws can act as an SSH agent. It wraps the existing
SSH agent running on `SSH_AUTH_SOCK`, and when it receives a request and if it
is the WebAuthn request, it'll process it. Otherwise, it'll forward the request
to the original SSH agent that was specified by `SSH_AUTH_SOCK` when it started.

The WebAuthn request-response is specified by [Web Authentication:
An API for accessing Public Key Credentials Level
2](https://www.w3.org/TR/webauthn-2/). For details, see
`./pkg/webauthn/webauthn.go`.

## Security

jc2aws's WebAuthn over SSH agent protocol should be used with caution.

* Same as SSH agent forwarding, use with only a trusted, non-shared server.
* Unlike the SSH agent forwarding, the created AWS credential can be used even
  after you disconnect the SSH client with limited time. As long as you use this
  with a trusted, non-shared server, usually this should not be a problem
  though.
