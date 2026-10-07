# s7comm-tags

Show PLC tag names and decoded values inside Wireshark, for Siemens S7comm traffic.

Wireshark on its own shows an S7comm packet as "read 24 bytes from DB40 at byte 0" followed by raw bytes. With this plugin the same packet gets an **S7 Tag Values** section in the packet details:

```
S7 Tag Values: read response, 26 tags from 3 devices
    Request in frame: 412
    VLV301   (14 tags in this packet, 22 defined)
        OpenCmd = True   (DB20,X2.0, Boolean)
        Ready = True     (DB20,X2.3, Boolean)
        ...
    PRS210   (11 tags in this packet, 18 defined)
        PV = 3.72        (DB40,D12, Float)
        ...
    TMP120   (1 tag in this packet, 26 defined - lone tag)
        Scale.RawMax = 16000   (DB60,D48, Float)
```

Tags are grouped by device: the part of the tag name before the first dot. Each device is a node that opens to show its tags, and its title says how many of its tags are in this packet and how many the tag CSV defines for it in total. A device with one tag in the packet out of several defined is marked `lone tag`. All tag names, addresses and values in this README are made up for illustration.

What is decoded:

| Packet | Shown |
|---|---|
| Read Var request | The tags being asked for |
| Read Var response | The tags and the values the PLC returned |
| Write Var request | The tags and the values being written. Also added to the Info column: `[WRITE TMP120.Scale.RawMax = 12.5]` |
| Write Var response | The tags and whether the PLC accepted the write |

## Requirements

- Wireshark with Lua support (the standard installers include it; tested on 4.6)
- Python 3.8 or newer, for the `s7tags.py` management script only
- A tag CSV: the tag list of the PLC, with at least these columns

  | Column | Example |
  |---|---|
  | `Tag Name` | `PRS210.PV` |
  | `Address` | `DB40,D12` (byte 12 of DB40) or `DB20,X2.3` (byte 2, bit 3) |
  | `Data Type` | `Boolean`, `Float`, `Long`, `DWord`, `Short`, `Int`, `Word`, `Byte` |

  This is the same file format that Mickael's s7comm-parser tool uses.

  **The tag CSV is not part of this repository**, because it describes a specific plant. Authorized team members can download it from the team's shared drive. For any other PLC, export the tag list from its engineering or OPC software with the three columns above.

## Install

```bash
python s7tags.py install path/to/tags.csv
```

Replace `path/to/tags.csv` with the location of your copy of the tag CSV (see Requirements for where to get it). If the command says `file not found`, the path does not point to the file: check where you saved it, and put the path in quotes if it contains spaces.

Then restart Wireshark. The script copies the plugin and the tag CSV into Wireshark's personal Lua plugins folder.

| Command | What it does |
|---|---|
| `python s7tags.py install [<csv> ...]` | Installs or updates the plugin, optionally with tag CSVs |
| `python s7tags.py add <csv> [...]` | Adds tag CSVs. A CSV with the same file name is replaced |
| `python s7tags.py replace <csv> [...]` | Removes all installed tag CSVs and uses the given ones instead |
| `python s7tags.py remove <name.csv> [...]` | Removes installed tag CSVs, by the file name shown in `list` |
| `python s7tags.py list` | Shows the installed tag CSVs |
| `python s7tags.py uninstall` | Removes the plugin and all tag CSVs |

After changing only the tag CSVs, pressing Ctrl+R in Wireshark is enough.

## Using it in Wireshark

Open a capture with S7comm traffic and click a packet. The **S7 Tag Values** section is at the bottom of the packet details. Clicking a tag highlights its bytes in the hex view.

Display filters:

| Filter | Finds |
|---|---|
| `s7tags` | Packets with at least one known tag |
| `s7tags.operation == "write request"` | Writes to known tags. Other values: `read request`, `read response`, `write response` |
| `s7tags.tag == "PRS210.PV"` | Packets that carry this tag |
| `s7tags.reading == "VLV301.Ack=True"` | Packets where this tag has this value |
| `s7tags.tag == "TMP120.Scale.RawMax" && s7tags.operation == "write request"` | Writes to one tag |
| `s7tags.device == "TMP120"` | Packets that carry any tag of this device |
| `s7tags.single` | Packets that touch exactly one tag of a device that has several |
| `s7tags.single == "TMP120"` | The same, for one device |
| `s7tags.single && s7tags.operation == "write request"` | Writes that change one lone tag |

Useful additions:

- **Find who changes a tag:** filter on the tag with `s7tags.operation == "write request"`, then look at the source address.
- **Show a tag in a column:** right-click a tag line in the packet details and choose *Apply as Column*.
- **Color all writes:** *View → Coloring Rules*, add a rule with the filter `s7tags.operation == "write request"`.

### Lone tags

A device is the part of the tag name before the first dot: `TMP120.Scale.RawMax` belongs to `TMP120`. HMI polling normally reads whole blocks, so many tags of a device appear together. `s7tags.single` marks packets where a device appears with exactly one of its tags.

On its own this is noisy, because HMIs also poll some tags alone as part of normal operation. It becomes useful when combined with a write filter, or with a specific tag that is not normally read alone:

```
s7tags.tag == "TMP120.Scale.RawMax" && !(s7tags.tag == "TMP120.Scale.RawMin")
```

## Speed

Listing every tag in every polling packet would make a capture load many times slower. So for read packets the plugin lists tags only when they are needed: when you click the packet, or when a filter or column uses `s7tags.tag`, `s7tags.value` or `s7tags.reading`. Writes are rare and are always decoded.

In testing on a large capture, a filter pass with the plugin took somewhat longer than with the plugin disabled, also when filtering on a tag name or a reading.

## Limits

- Only the DB area is decoded (addresses like `DB40,D12`), for Read Var and Write Var.
- A response is matched to its request by TCP stream and PDU reference. If the request is not in the capture (for example, at the very start of a split file), the response is not decoded.
- `Long` is shown as a signed 32-bit number.
- Tag names and values are text fields, so a filter cannot compare numerically ("value > 5").

## How it works

The plugin (`s7comm_tags.lua`) is a Wireshark post-dissector. It reads the fields Wireshark's own S7comm dissector already extracted (DB number, byte address, length, returned data), looks up which tags lie in each requested byte range, and decodes each tag from the data bytes according to its type.

## Credits

The decoding method is based on the s7comm-parser tool by Mickael: matching each Read Var response to its request, finding the tags inside each requested byte range, and decoding each tag by its data type. This plugin applies the same method inside Wireshark and adds Write Var decoding.

The plugin's output was checked against s7comm-parser on its example capture, and all readings had identical values.
