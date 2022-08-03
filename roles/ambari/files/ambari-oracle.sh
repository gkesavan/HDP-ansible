#!/bin/bash
alter session set "_ORACLE_SCRIPT"=true;
CREATE USER ambari IDENTIFIED BY ambari123 default tablespace "USERS" temporary tablespace "TEMP";
GRANT unlimited tablespace to ambari;
GRANT create session to ambari;
GRANT create TABLE to ambari;
GRANT create SEQUENCE to ambari;
QUIT;
