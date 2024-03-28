create or replace package body "OAUTH_PKG" as

uid varchar2(100) := '926419511';  -- arbitrary value to be used for csrf token

function setPwd(p_user varchar2, p_password varchar2)
return varchar2
is

 l_ccn_raw RAW(256) := utl_raw.cast_to_raw(p_password);
 l_encrypted_raw RAW(2048);

begin
    l_encrypted_raw := dbms_crypto.hash(l_ccn_raw, 3);
    update OAUTH_USERS set pwd = l_encrypted_raw where login = p_user;
    commit;
    return '0';
end;

function checkPwd(p_user varchar2, p_password varchar2)
return boolean
is
    l_ccn_raw RAW(256) := utl_raw.cast_to_raw(p_password);
    l_encrypted_raw RAW(2048);
    tpwd varchar2(100);
begin
    l_encrypted_raw := dbms_crypto.hash(l_ccn_raw, 3);
    select pwd into tpwd from oauth_users where login = p_user;
    if tpwd =  dbms_crypto.hash(l_ccn_raw, 3) then
        return true;
    else
        return false;
    end if;
end;

function auth (
    p_client_id in varchar2,
    p_username in varchar2,
    p_password in varchar2,
    p_ref   in varchar2 )
    return varchar2
is
    l_user oauth_users.login%type := upper(p_username);
    l_pwd oauth_users.pwd%type;
    l_values apex_json.t_values;
    l_clob    CLOB; 
    tendpoint varchar2(1000); --'https://xxx.xxx.xxx/ords/<SCHEMA>/oauth/token';  
    lclientid varchar2(100); 
    lclientpwd  varchar2(100); 
    l_param_names apex_application_global.vc_arr2;
    l_param_values apex_application_global.vc_arr2;
    ltoken varchar2(1000);
    --tflow varchar2(50) := 'client_credentials' ;
    tjson apex_json.t_values; 
    l_auth varchar2(500);
    luri varchar2(1000);
    req   UTL_HTTP.REQ;
    resp  UTL_HTTP.RESP;
       l_buffer           VARCHAR2(32767); 

begin
    tendpoint := substr(p_ref, 1, 
                        (instr(p_ref, '/custauth')-1)
                 ) || '/oauth/token';

    l_auth := utl_encode.text_decode('xxx:xxx','WE8ISO8859P1', UTL_ENCODE.BASE64);
     
    -- Check Password 
    if not checkPwd(p_username, p_password)
        then return ('-1');
    end if;     
     
    -- ---------------------------------
    -- Get client secret
    -- ---------------------------------

    lclientid := p_client_id;

    begin
        SELECT client_secret into lclientpwd 
        FROM   user_ords_clients
        where client_id = lclientid;
    exception
    when others then
        return ('-3');
    end;    

    apex_web_service.g_request_headers(1).name  := 'Content-Type'; 
    apex_web_service.g_request_headers(1).value := 'application/json';
    apex_web_service.g_request_headers(2).name  := 'Authorization'; 
    --l_param_names(1) :='grant_type';
    --l_param_values(1) := 'client_credentials' ; 
    -- encode cliendid and secret in base64. Remove NL-CR ))
    l_auth :=    
    replace(UTL_RAW.CAST_TO_VARCHAR2(
                UTL_ENCODE.BASE64_ENCODE(
                        UTL_RAW.CAST_TO_RAW(
                            lclientid ||':'||lclientpwd
                        )
                    )
                ), chr(13)||chr(10)
            );
    --utl_encode.text_encode('xxxxxx:xxxxxxxx','WE8ISO8859P1', UTL_ENCODE.BASE64);
    apex_web_service.g_request_headers(2).value := 'Basic ' || l_auth;
        
    -- get token 
    
        l_clob := APEX_WEB_SERVICE.make_rest_request( 
            p_url         => tendpoint ||'?grant_type=client_credentials',
            p_http_method => 'POST'
    
        ); 
    
        apex_json.parse(tjson, l_clob);
        ltoken := APEX_JSON.get_varchar2(p_path => 'access_token', p_values => tjson);
        
        /* variant with utl_http 
        -- get token 
        req := UTL_HTTP.BEGIN_REQUEST(tendpoint ||'?grant_type=client_credentials', 'POST');
        UTL_HTTP.SET_HEADER(req, 'Content-Type', 'application/json');
        UTL_HTTP.SET_HEADER(req, 'Authorization', 'Basic ' || l_auth);
        resp := UTL_HTTP.GET_RESPONSE(req);
        utl_http.read_text(resp, l_buffer);
       
        l_token := l_buffer;
        UTL_HTTP.END_RESPONSE(resp);
    */

        -- Logs entry and update session in custom users table
        insert into oauth_log(dd,txt) values(sysdate, substr(l_clob,1,500));
        update OAUTH_USERS set token=ltoken where upper(login) = upper(p_username);
        commit;
    
    return ltoken;

end; 
FUNCTION generate_csrf_token
RETURN VARCHAR2
IS
    v_token VARCHAR2(64); -- 
    v_random VARCHAR2(32);
    v_timestamp TIMESTAMP;
BEGIN
    -- Generates a random 32 c length string
    --SELECT DBMS_RANDOM.STRING('X', 32) INTO v_random FROM DUAL;

    -- uses timestamp to enforce unicity
    SELECT SYSTIMESTAMP INTO v_timestamp FROM DUAL;

    --Concatenates with an arbitrary id 
    v_token := uid || TO_CHAR(v_timestamp, 'YYYYMMDDHH24MISSFF');

    -- Hash with MD5
    v_token := DBMS_CRYPTO.HASH(UTL_I18N.STRING_TO_RAW(v_token, 'AL32UTF8'), DBMS_CRYPTO.HASH_MD5);

    RETURN v_token;
end generate_csrf_token;

function getLogin(p_auth varchar2)
return varchar2
is
    l_login varchar2(50);
begin
    select login into l_login
                    from oauth_users 
                    where token = replace(p_auth, 'Bearer ') ;
                   
    return l_login;
exception
    when others then return '-1';
end;

-- for debug.
-- Must be ignored
function authutl (
    p_client_id in varchar2,
    p_username in varchar2,
    p_password in varchar2,
    p_ref   in varchar2 )
    return varchar2
is
    l_user oauth_users.login%type := upper(p_username);
    l_pwd oauth_users.pwd%type;
    l_values apex_json.t_values;
    l_clob    CLOB; 
    tendpoint varchar2(1000); --'https://xxx.xxx.xxx/ords/<SCHEMA>/oauth/token';  
    lclientid varchar2(100); 
    lclientpwd  varchar2(100); 
    l_param_names apex_application_global.vc_arr2;
    l_param_values apex_application_global.vc_arr2;
    ltoken varchar2(1000);
    --tflow varchar2(50) := 'client_credentials' ;
    tjson apex_json.t_values; 
    l_auth varchar2(500);
    luri varchar2(1000);
    req   UTL_HTTP.REQ;
    resp  UTL_HTTP.RESP;
    val VARCHAR2(1024);
    x_clob             CLOB;
    l_buffer           VARCHAR2(32767); 

begin
    tendpoint := substr(p_ref, 1, 
                        (instr(p_ref, '/custauth')-1)
                 ) || '/oauth/token';
    tendpoint := 'xxxxxxxx/ords/demo/oauth/token';
    l_auth := utl_encode.text_decode('xxx:xxx','WE8ISO8859P1', UTL_ENCODE.BASE64);
     
    -- Check Password 
    if not checkPwd(p_username, p_password)
        then return ('-1');
    end if;     
     
    -- ---------------------------------
    -- Get client secret
    -- ---------------------------------

    lclientid := p_client_id;

    begin
        SELECT client_secret into lclientpwd 
        FROM   user_ords_clients
        where client_id = lclientid;
    exception
    when others then
        return ('-3');
    end;    

    -- encode cliendid and secret in base64. Remove NL-CR ))
    l_auth :=    
    replace(UTL_RAW.CAST_TO_VARCHAR2(
                UTL_ENCODE.BASE64_ENCODE(
                        UTL_RAW.CAST_TO_RAW(
                            lclientid ||':'||lclientpwd
                        )
                    )
                ), chr(13)||chr(10)
            );

        
    -- get token 
    req := UTL_HTTP.BEGIN_REQUEST(tendpoint ||'?grant_type=client_credentials', 'POST');
    UTL_HTTP.SET_HEADER(req, 'Content-Type', 'application/json');
    UTL_HTTP.SET_HEADER(req, 'Authorization', 'Basic ' || l_auth);
    resp := UTL_HTTP.GET_RESPONSE(req);
    utl_http.read_text(resp, l_buffer);
    
    
    val := l_buffer;
    UTL_HTTP.END_RESPONSE(resp);
        
        -- Logs entry and update session in custom users table
        insert into oauth_log(dd,txt) values(sysdate, substr(val,1,500));
        --update OAUTH_USERS set token=ltoken where upper(login) = upper(p_username);
        commit;
    
    return val;

end; 

end "OAUTH_PKG";
/