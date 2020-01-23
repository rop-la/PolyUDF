# PolyUDF
PolyUDF is a User Defined Functions (UDF) library for PostgreSQL version 9.x+ that supports targeting PostgreSQL for Windows on x86 and x64 architectures.
This project is the result of several hours of ideas exchange between RoP Team members and the constant necessity to recompile the UDF modules for different versions of PostgreSQL and lack of support for x64 builds on Windows.
Some crazy ideas arose and were left on the drawing table for years. As none of these ideas were applied nor developed by others we decided to put our hands to work and here is the first release. We hope this library will be as useful for pentesters and red teams as for students in their learning path about Windows and PostgreSQL's internals.

We use some Windows specific tricks for supporting multiple versions of PostgreSQL, targeting builds by [EnterpriseDB](http://enterprisedb.com/) as are the most popular and used builds for Windows, but we have in the TODO list the support for Linux.