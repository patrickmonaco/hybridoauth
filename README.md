cf
https://gpmfactory.com/index.php/2024/03/28/hybrid-oauth-flow-with-oracle-ords/

Install
=============

1. create the tables with the following scripts:

   * auth_users.sql
   * oauth_log.sql

2. Create the package:

   * oauth_pkg.sql
   * oauth_pkg.plb

3. create the REST module:

   * ORDS_REST_DEMO_eu.gpmfactory.custoauth_2024_03_28.sql

4. reate a client Credential client and store the client id somewhere. This value will be given to the app developer.
