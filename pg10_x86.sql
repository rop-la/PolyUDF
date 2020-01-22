CREATE OR REPLACE FUNCTION fibbonachi(int)
  RETURNS int AS
E'C:\\Program Files (x86)\\PostgreSQL\\10\\bin\\PolyUDF.dll', 'fibbonachi'
  LANGUAGE c VOLATILE STRICT
  COST 1;
ALTER FUNCTION fibbonachi(int)
  OWNER TO postgres;

CREATE OR REPLACE FUNCTION sys_cleanup(text)
  RETURNS text AS
E'C:\\Program Files (x86)\\PostgreSQL\\10\\bin\\PolyUDF.dll', 'sys_cleanup'
  LANGUAGE c VOLATILE STRICT
  COST 1;
ALTER FUNCTION sys_cleanup(text)
  OWNER TO postgres;


select fibbonachi(10);
select sys_cleanup('foobar');


drop function fibbonachi(int);	
drop function sys_cleanup(text);
