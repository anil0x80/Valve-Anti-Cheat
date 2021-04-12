# Valve-Anti-Cheat
Includes various projects that I coded to reverse the famous anti cheat of Valve.
The analysis were done on the game Counter Strike: Global Offensive, but procedure is pretty much same for any VAC game.

# VAC Emulator:
Contains code that can call any VAC modules that was previously reversed.
This emulates correct Ice Key encryption required to run a VAC module.
Most of the work (really, a lot) is put into definitions of modules, as they were all reverse engineered with IDA.

# VAC Dumper
Dumps VAC modules on-fly as they are streamed from server to the client.
Also dumps the input&output bytes and encryption&decryption keys so reversing the module is possible afterwards.
Must be injected into steam client.
