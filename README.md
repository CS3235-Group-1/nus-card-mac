# nus-card-mac
Checks the MAC of the matric card or writes a MAC onto a matric card

Compile
---------
Compile with gcc. Also include `-lnfc` and `-lfreefare` and `-lopenssl`

`gcc mifare-check-digital-signature.c -o nus-mac -lnfc -lfreefare -lopenssl`

Execute
--------
Then run the executable. Place the MIFARE CLASSIC 1K card on the reader first. The options are `c` to check the validity of the MAC and `w` to write a MAC onto sector 15 of the matriculation card.

`./nus-mac -c`
