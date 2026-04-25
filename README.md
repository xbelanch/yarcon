# yarcon

Yet Another RCON is a small console client for sending administration commands to game servers over RCON. The code is protocol-oriented rather than game-specific: yarcon currently speaks Source RCON over TCP and Battleye RCON over UDP, then passes the command text through to the server.

## Protocol Support

| Protocol | Transport | Typical servers |
| --- | --- | --- |
| Source RCON | TCP | Source Dedicated Server games, Project Zomboid, 7 Days to Die, Rust Legacy, Minecraft Java servers that expose Source-style RCON |
| Battleye RCON | UDP | DayZ, Arma 2/3 and other Battleye-enabled servers |

Game support depends on the server exposing a compatible RCON endpoint and accepting the command you send. yarcon does not maintain game-specific sessions or command parsers.

## Installing

Build the binary with the bundled script:

```sh
./build.sh
```

The script compiles the CLI entry point in `yarcon.c` with `gcc` and writes the executable to `./yarcon`.

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
- `-d, --debug`: print connection settings and protocol-level packet traces before sending the command.
- `-h, --help`: print usage information.

Examples:

```sh
# Source RCON
./yarcon -H 127.0.0.1 -p 27015 -P password -c status

# Minecraft Java RCON
./yarcon -H 127.0.0.1 -p 25575 -P password -c list

# Battleye RCON
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

## Debugging

Use `-d` when an RCON server connects but does not answer as expected:

```sh
./yarcon -d -H 127.0.0.1 -p 25575 -P password -c list
./yarcon -b -d -H 127.0.0.1 -p 2301 -P password -c players
```

Debug output goes to `stderr` and includes:

- TCP connection start and success.
- Source RCON packets sent and received with `size`, `id`, `type`, total length and body length.
- Auth response and auth confirmation packets. A failed password is shown as `id=-1`.
- Battleye UDP packets sent and received with packet size, payload size, checksum, packet type and body preview.
- Read failures as `timeout`, `connection closed`, `socket error`, or `malformed packet`.

The auth password body is redacted in debug output. Command and response bodies are shown as escaped previews.

## Command Examples

RCON commands are owned by each game server, not by yarcon. Treat the table below as a starting point and check your server's current command reference before using destructive commands such as ban, kick, shutdown, restart, or save.

| Server family | Protocol flag | Useful discovery commands | Common administration commands |
| --- | --- | --- | --- |
| Source Dedicated Server games | default Source RCON | `status`, `cvarlist`, `help <command>` | `say <message>`, `kick <name or userid>`, `banid <minutes> <steamid>`, `changelevel <map>` |
| Project Zomboid | default Source RCON | `players`, `help` | `servermsg "message"`, `save`, `quit`, `kickuser "username" -r "reason"`, `banuser "username"` |
| 7 Days to Die | default Source RCON | `help`, `listplayers`, `version` | `say "message"`, `kick <entityid or steamid> <reason>`, `ban add <name or id> <duration> <reason>`, `saveworld`, `shutdown` |
| Rust Legacy | default Source RCON | `status`, `find .` | `say "message"`, `kick "player"`, `banid <steamid>`, `save.all` |
| DayZ / Arma Battleye | `-b, --battleye` | `commands`, `version`, `players`, `admins` | `say -1 <message>`, `kick <player #> <reason>`, `ban <player #> <minutes> <reason>`, `bans`, `removeBan <ban #>` |
| Arma server commands through Battleye | `-b, --battleye` | `missions`, `players` | `#missions`, `#mission <missionName>`, `#restart`, `#reassign`, `#shutdown` |
| Minecraft Java RCON | default Source RCON-compatible framing | `list`, `help` | `say <message>`, `kick <player> [reason]`, `ban <player> [reason]`, `save-all`, `stop` |

Some games require commands to be entered without the in-game slash when sent through RCON. For example, an in-game `/save` command may be sent as `save`.

For Minecraft Java, enable RCON in `server.properties` before connecting:

```properties
enable-rcon=true
rcon.password=password
rcon.port=25575
```

### Minecraft Golden Age / Beta 1.7.3

Minecraft Beta 1.7.3, often treated as the "Golden Age" release, does not implement RCON. Minecraft Java RCON was introduced later, in Beta 1.9 Prerelease. Publishing or exposing port `25575` in Docker is not enough: the `server.jar` itself must open and speak RCON on that port.

For a Beta 1.7.3 server, this can look misleading:

```txt
docker-compose ps   # shows 25575:25575 published
ss on the host      # shows Docker listening on 0.0.0.0:25575
nc from a client    # returns "Connection refused"
```

In that case yarcon is not reaching an RCON server; Docker is publishing a port that the Minecraft process inside the container does not actually serve. Check from inside the container:

```sh
docker exec -it mc-beta173 sh
ss -ltnp
grep -i rcon /data/server.properties
```

If only `25565` is listening and there are no `enable-rcon`, `rcon.password`, or `rcon.port` properties, the server version has no native RCON support. Use a newer Minecraft Java server, a mod/wrapper/proxy that exposes remote console control, or manage the process through Docker/stdin/logs instead of RCON.

## Implementation Notes

- `yarcon.c` is the production CLI entry point.
- `yarcon.h` contains packet helpers for Source and Battleye RCON.
- Source RCON reads now follow Minecraft-compatible packet framing: read the 4-byte size first, read the exact payload length, and reject failed auth responses.
- `game_response.h` contains optional, game-agnostic response parsing helpers for future command-specific features.
- Game-specific experiments and hardcoded probe code have been removed from the default project tree so the client stays protocol-focused.

The current CLI validates required arguments, checks port ranges, bounds packet payloads before serialization, avoids config parser leaks, and sends the whole TCP packet even when `send(2)` writes only part of the buffer.

## References

- [Source RCON Protocol](https://developer.valvesoftware.com/wiki/Source_RCON_Protocol)
- [Battleye RCON Protocol](https://www.battleye.com/downloads/BERConProtocol.txt)
- [Project Zomboid dedicated server](https://pzwiki.net/wiki/Dedicated_server)
- [Project Zomboid administration commands](https://citadelservers.com/wiki/index.php?title=Administrating_a_server_in_Project_Zomboid)
- [7 Days to Die serveradmin.xml command permissions](https://wiki.7d2d.net/game/serveradmin-xml/)
- [Bohemia BattlEye RCON notes](https://community.bohemia.net/wiki/BattlEye)
- [Minecraft server commands](https://minecraft.wiki/w/Commands)
- [@n0la rcon](https://github.com/n0la/rcon)
- [@Tiiffi mcrcon](https://github.com/Tiiffi/mcrcon)
- [rconc](https://git.kasad.com/rconc/about/)
- [@MultiMote battleye-rcon implemented in C](https://gist.github.com/MultiMote/169265fd74fe94b44941c1b05b296f0d)
- [How to Code a Server and Client in C with Sockets on Linux – Code Examples](https://www.binarytides.com/server-client-example-c-sockets-linux/)
- [Simple C example of doing an HTTP POST and consuming the response](https://stackoverflow.com/questions/22077802/simple-c-example-of-doing-an-http-post-and-consuming-the-response)
- [Battleye RCON c test](https://gist.github.com/MultiMote/169265fd74fe94b44941c1b05b296f0d)
