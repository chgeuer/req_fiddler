# `:req_fiddler` - Inject MITM proxy settings into your Req pipeline

This package works both on **Windows**, and on **Windows Subsystem for Linux (WSL)**. 

In the simplest case, you must call `ReqFiddler.attach()` on a `%Req.Request{}` struct and it injects itself. It that does a few things:

- Use `reg.exe` to read from the Windows registry whether there's a proxy configured.
- Use `ipconfig.exe` to enumerate the host's local IP addresses, and assume there is one that starts with `192.168`.
- Fetch the Fiddler CA certificate by calling the Windows host's Fiddler port and get the certificate from ` "http://#{ip_address}:#{port}/FiddlerRoot.cer"`
- Configure the proxy on the `Req.Request`.

Oh, and if there's no proxy configured, that handler is just skipped.

## Installation

The package can be installed by adding `req_fiddler` to your list of dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:req_fiddler, github: "chgeuer/req_fiddler"}
  ]
end
```

## Usage

```elixir
Req.new()
|> ReqFiddler.attach()
|> Req.merge(method: :get, url: "https://hex.pm/")
|> Req.request!() 
```

### Screenshot from this session

You can see that first it fetches the MITM CA certificate from `http://192.168.1.172:8888/FiddlerRoot.cer` and then tunnels to `hex.pm`, and Fiddler injects itself as man-in-the-middle:

![](content/fiddler_screenshot.png)

