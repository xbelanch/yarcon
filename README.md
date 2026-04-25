# yarcon

Yet Another RCON is a console client that implements both Source and Battleye RCON protocol. You can execute commands on remote game servers for administration and maintenance.

## Supported Games Servers

  * [x] 7 Days to Die
  * [x] Arma3
  * [x] DayZ
  * [x] Project Zomboid
  * [x] Rust Legacy
  * [ ] Arma2
  * [ ] Minecraft
  * [ ] Rust

## Installing

Build the binary with the bundled script:

```sh
./build.sh
```

The script compiles `yarcon.c` with `gcc` and writes the executable to `./yarcon`.

Requirements:

- Linux or another POSIX-like system with sockets support
- `gcc`
- `bash`

## Usage

```sh
./yarcon -H HOST -p PORT -P PASSWORD -c COMMAND [OPTIONS]
```

Required arguments:

- `-H, --host HOST`: server host name or IP address.
- `-p, --port PORT`: RCON port. It must be a number from 1 to 65535.
- `-P, --password PASS`: RCON password.
- `-c, --command CMD`: command to run on the server.

Options:

- `-b, --battleye`: use Battleye RCON over UDP. Without this flag, yarcon uses Source RCON over TCP.
- `-f, --config FILE`: read `host` and `port` from a config file. CLI values take precedence.
- `-d, --debug`: print connection settings before sending the command.
- `-h, --help`: print usage information.

Examples:

```sh
# Project Zomboid / Source RCON
./yarcon -H 127.0.0.1 -p 16261 -P password -c players

# DayZ / Battleye RCON
./yarcon -b -H 127.0.0.1 -p 2301 -P password -c players
```

Config files support `host: value` and `port: value` lines:

```txt
host: 127.0.0.1
port: 16261
```

Then run:

```sh
./yarcon -f server.conf -P password -c players
```

## Implementation Notes

- `yarcon.c` is the production CLI entry point.
- `yarcon.h` contains packet helpers for Source and Battleye RCON.
- `pzserver.h` contains Project Zomboid parsing helpers. It returns `-1` for malformed player-count output instead of reading past the input or leaking memory.
- `main.c` is preserved only as a documented legacy Project Zomboid probe. It is not compiled by `build.sh` because it contains hardcoded connection data and one-off experimental flow.

The current CLI validates required arguments, checks port ranges, bounds packet payloads before serialization, avoids config parser leaks, and sends the whole TCP packet even when `send(2)` writes only part of the buffer.

## References

- [Source RCON Protocol](https://developer.valvesoftware.com/wiki/Source_RCON_Protocol)
- [Battleye RCON Protocol](https://www.battleye.com/downloads/BERConProtocol.txt)
- [@n0la rcon](https://github.com/n0la/rcon)
- [@Tiiffi mcrcon](https://github.com/Tiiffi/mcrcon)
- [rconc](https://git.kasad.com/rconc/about/)
- [@MultiMote battleye-rcon implemented in C](https://gist.github.com/MultiMote/169265fd74fe94b44941c1b05b296f0d)
- [How to Code a Server and Client in C with Sockets on Linux – Code Examples](https://www.binarytides.com/server-client-example-c-sockets-linux/)
- [Simple C example of doing an HTTP POST and consuming the response](https://stackoverflow.com/questions/22077802/simple-c-example-of-doing-an-http-post-and-consuming-the-response)
- [Battleye RCON c test](https://gist.github.com/MultiMote/169265fd74fe94b44941c1b05b296f0d)
