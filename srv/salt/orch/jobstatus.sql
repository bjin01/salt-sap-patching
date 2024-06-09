select a.server_id, b.name, c.server_name 
from rhnserveraction a, rhnactionstatus b, rhnserveroverview c 
where a.action_id = 28475 AND c.server_name = 'pxesap02.bo2go.home' 
AND a.server_id = c.server_id AND b.id = a.status;
