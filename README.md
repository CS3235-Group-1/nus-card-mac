# nus-card-check-signature
Checks the signature of the matric card.

Compile
---------
Compile with gcc into the output file `check`. Needs the `-std=c99` param due to some shiz in the code. Also include `-lnfc` and `-lfreefare`. Don't ask why.

`gcc mifare-check-digital-signature.c -o check -std=c99 -lnfc -lfreefare`

Execute
--------
Then run the executable. Place the MIFARE CLASSIC 1K card on the reader first, duh. If you don't have a reader, why are you even reading this???

`./check`

Output
--------
The output of the program should be clear enough. If it's not clear enough, you obviously didn't follow the instructions above. Too bad. Submit an issue to `/dev/null`.
