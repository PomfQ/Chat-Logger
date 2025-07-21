# KoGaMa Chat Monitor

A Python-based tool designed to **monitor in-game chat traffic** in KoGaMa by targeting specific UDP packets. While functional, the tool is **not 100% accurate** and may occasionally display false or partial information — use with caution.

---

## [⚙️] How It Works

- **Target Port**: Listens to KoGaMa’s UDP traffic on port `5055`, specifically connected to the following server IPs:
  - `85.17.83.193`
  - `85.17.124.179`

- **Packet Detection**: Filters and processes packets containing the `CHAT_HEADER`, defined as:
``b"\x62\x05\x73\x00"``

- **Decoding**:
- `latin1` is used for standard Latin-based characters.
- `utf-8` is used for decoding **non-Latin scripts** (such as Arabic, Cyrillic, Chinese, etc.).

- **Output Format**:  
Messages are printed to the console in the format:
[Username] : [Message]


If the username is unavailable, the script will fall back to displaying the actor ID:
[Actor_1] : [Message]

- **Private Chat Support**:  
This tool can also capture **private chat traffic**, including *Team chat* and other non-global channels.

---

## [⚠️] Limitations

- The script **cannot resolve usernames** for players who were already in the session **before** it was launched.
- However, it will still display their **actor ID** when they send messages.

---

## [💬] Example Output

![Output Example](https://cdn.discordapp.com/attachments/1264627993477906584/1396865876325826610/image.png?ex=687fa439&is=687e52b9&hm=4b9c239add3ec4257cd64c4e3a270d0727a12945c4d552ab31f834a421cb59a1&)

## Credits

Developed by M

[🤝] Special thanks to :

- tuba zhoao pedro
- Devork (For the Idea)

## 🚨 Disclaimer

This tool is intended for **educational and debugging purposes only**. Be mindful of privacy, terms of service, and ethical use when sniffing traffic in multiplayer environments. <br>

⚠️ Use at your own risk. I take no responsibility if this results in a ban or any other consequences.
