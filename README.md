# sss_deobfuscate

Decode / decrypt / de-obfuscate LDAP password from `sssd.conf` that has been *obfuscated* with `sss_obfuscate`.

```
~ # cat /etc/sssd/sssd.conf
[domain/LDAP]
ldap_default_authtok = AAAQABagVAjf9KgUyIxTw3A+HUfbig7N1+L0qtY4xAULt2GYHFc1B3CBWGAE9ArooklBkpxQtROiyCGDQH+VzLHYmiIAAQID
ldap_default_authtok_type = obfuscated_password
...
```

Simply pass the encrypted password to the script as a parameter:

```
~ # ./sss_deobfuscate AAAQABagVAjf9KgUyIxTw3A+HUfbig7N1+L0qtY4xAULt2GYHFc1B3CBWGAE9ArooklBkpxQtROiyCGDQH+VzLHYmiIAAQID
Decoded password: Passw0rd
```

## Author

Michael Ludvig
