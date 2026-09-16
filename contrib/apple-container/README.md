# totan in the apple/container init image

`container` boots every container in a lightweight VM whose init process is
`vminitd`. This image wraps that init with `totan-vminit`, so totan starts in
the VM and intercepts the egress of everything that runs in it. The proxy
settings live in the VM instead of in each container image.

The release workflow builds the `Containerfile` here on a tag and pushes the
result as `ghcr.io/matchascript/totan-init:<version>` for arm64.

## Put your proxy in

The published image carries `config.example.toml` as `/etc/totan/config.toml`,
with a placeholder address. Your own address stays on your machine: keep two
files in a directory of your own, for example `~/.config/totan/`.

`config.toml` — a copy of `config.example.toml` with your `default_proxy`.

`Containerfile`:

```
FROM ghcr.io/matchascript/totan-init:0.1.0
COPY config.toml /etc/totan/config.toml
```

Build it:

```
container build -t local/totan-init ~/.config/totan
```

## Use it for every container

Add the image to `~/.config/container/config.toml`:

```
[vminit]
image = "local/totan-init"
```

`container system stop && container system start` picks up the change. A single
container can also take it with `container run --init-image local/totan-init`.

## Check that it runs

```
container logs --boot <container> | grep totan-vminit
```
