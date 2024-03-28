create or replace package "OAUTH_PKG" as

-- -------------------------------------------------------------------
-- checks credentials then generates a valid token
-- -------------------------------------------------------------------

function auth (
    p_client_id in varchar2,
    p_username in varchar2,
    p_password in varchar2,
    p_ref   in varchar2 )
    return varchar2;

function authutl (
    p_client_id in varchar2,
    p_username in varchar2,
    p_password in varchar2,
    p_ref   in varchar2 )
    return varchar2;

-- -------------------------------------------------------------------
-- computes a hash for a password
-- ------------------------------------------------------------------- 

function setPwd(p_user varchar2, p_password varchar2)
return varchar2;

-- -------------------------------------------------------------------
-- Generates a anti CSRF token to be put in the login form 
-- ------------------------------------------------------------------- 

function generate_csrf_token
return varchar2;

-- -------------------------------------------------------------------
-- Extracts token from Authorization header then fetch user login
-- ------------------------------------------------------------------- 

function getLogin(p_auth varchar2)
return varchar2;

end "OAUTH_PKG";
/