# Netflow V5 TCP packet exportér p2nprobe

## Základní informace

Autor: Patrik Uher

Login: xuherp02

Datum: 18/11/2024

### Body

15/20

## Seznam odevzdaných souborů

- složka src se soubory: p2nprobe.cpp, client-args.cpp, flow.cpp, flow-manager.cpp, debug-info.cpp, packet-composer.cpp, 
p2nprobe.hpp, client-args.hpp, flow.hpp, flow-manager.hpp, debug-info.hpp, packet-composer.hpp

- složka pcap s pcap soubory, které byly použity při testování

- Makefile

- README.md

- manual.pdf

## Příklad spuštění

`./p2nprobe 127.0.0.1:2552 ./pcaps/10packets.pcap -a 15 -i 21` - spustí program aby na adresu 127.0.0.1, na port 2552 poslal packety
netflow v5, kde packety jsou ze souboru ./pcaps/10packets.pcap. Aktivní timeout je nastaven na 15 sekund a neaktivní timeout na 21 sekund.

`./p2nprobe localhost:1234 ./pcaps/249packets.pcap` - spustí program aby na adresu 127.0.0.1, na port 1234 poslal packety
netflow v5, kde packety jsou ze souboru ./pcaps/249packets.pcap. Aktivní timeout je nastaven na 60 sekund a neaktivní timeout na 60 sekund.

`./p2nprobe 192.168.10.5:1456 ./pcaps/1packet.pcap --debug` - spustí program aby na adresu 192.168.10.5, na port 1456 poslal packety
netflow v5, kde packety jsou ze souboru ./pcaps/1packet.pcap. Aktivní timeout je nastaven na 60 sekund a neaktivní timeout na 60 sekund.
Dále jsou nastaveny ladící výpisky, které vypíšou veškeré důležité informace o programu (varování program vypíše hodně
textu na standardní výstup).

`./p2nprobe --help` - vypíše pomocní text na to jak program používat.

## Textový popis: 

Program se chová jako exportér pro netflow v5 collector. Program čte packety a jejich obsah z pcap souboru a ty dále agreguje do toků.
Toky jsou agregovány podle jejich `source ip`, `destination ip`, `source port`, `destination port` a `ip protocol type`. Program je omezený
na agregaci TCP packetů a ostatní ignoruje. Program používá aktivní a neaktivní čas pro funkcionalitu expirace toků. Pokud tok je buď už
dlouho neaktivní a nebo pokud je tok už dlouho aktivní, tak tento tok se ukončí a další packety co by se do tohoto toku agregovaly, tak
jsou agregovány do nového toku. Podle specifikace zadání a netflow v5 pracuje program s relativním časem. Jako přesnost se v programu
používají microsekundy, které se, při odesílání netflow packetu na netflow collector, přetypují na milisekundy (dle specifikace netflow v5).
