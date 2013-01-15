kwalletcrack
============

KDE KWallet password cracker

1. Compile kwalletcrack ```make```

2. ```cat ~/magnum-jumbo/run/password.lst  | ./kwalletcrack <.kwl file>```

3. Do not use on .kwl files generated on different byte-order platforms (due to possible bug in KWallet's Blowfish implementation).

Speed: 1900+ passwords / second on AMD X3 720 CPU @ 2.8GHz (using single core).


For brute-forcing KDE KWallet files use JtR-jumbo instead of this program!
