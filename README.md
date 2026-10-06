# json2dir-compcert

json2dir in ISO C99 + POSIX, compiled with [CompCert](https://github.com/AbsInt/CompCert), the formally verified C compiler.

    ccomp -O -o out/json2dir json2dir.c && out/json2dir < document.json
