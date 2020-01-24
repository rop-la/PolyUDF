# PolyUDF
PolyUDF is a User Defined Functions (UDF) library for PostgreSQL version 9.4+ (version 1 calling convention) that supports targeting PostgreSQL for Windows on x86 and x64 architectures.
This project is the result of several hours of ideas exchange between RoP Team members and the constant necessity to recompile the UDF modules for different versions of PostgreSQL and lack of support for x64 builds on Windows.
Some crazy ideas arose and were left on the drawing table for years. As none of these ideas were applied nor developed by others we decided to put our hands to work and here is the first release. We hope this library will be as useful for pentesters and red teams as for students in their learning path about Windows and PostgreSQL's internals.

We use some Windows specific tricks for supporting multiple versions of PostgreSQL, targeting builds by [EnterpriseDB](http://enterprisedb.com/) and [2ndQuadrant](https://www.2ndquadrant.com/) as are the most popular and used builds for Windows, but we have in the TODO list the support for Linux.

The main features of PolyUDF are:
* Multiversion (9.4+ - version 1 calling convention) and architecture (x86/x64) support (Pretty obvious)
* Clean DLL and functions loading and registering (Register one function that register all!)
* Clean DLL and functions unloading and unregistering (Register one function that unregister all functions and unloads the DLL. No more service restart to delete DLL from disk and leave no trace.)

The current TODO List:
- [ ] Support for Linux
- [ ] Implement all functions required by SQLMap
- [ ] Integrate into SQLMap
- [ ] Validate and add support to 8.x - 9.3 versions (Version 0 calling convention)