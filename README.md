Unofficial mirror of pgenctypes
===============================

**[Link to original project on bitbucket](https://bitbucket.org/ivoras/pgenctypes/src/09a76f6a2c2b?at=default)**

*****

This project provides transparently encrypted data types for the PostgreSQL
database. With it, table schemas can be designed which contain one or more
data fields (columns) which are encrypted before being stored in the database.

The currently supported data types are:
  - "enctext"	- like the "text" data type
  - "encbigint"	- like the "bigint" data type
  - "encdouble"	- like the "double" data type

The encryption used is AES-256 in CFB mode, with random per-datum IVs.

See doc/UserGuide.txt for details.

The current status of this project is *alpha*.

Released under the 2-clause BSD license.
