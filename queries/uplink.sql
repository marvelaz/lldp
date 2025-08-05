/* ───────────────────────────────────────────────
   Cables with type violation
   – uplinks that are not CAT6 or Fibre
   
   This enforces a policy that uplink connections should only
   use CAT6 or Fibre cables for performance/reliability.
   ----------------------------------------------*/
SELECT cable_id,
       a_device,
       a_port,
       b_device,
       b_port,
       cable_type,
       cable_status,
       CASE 
         WHEN a_port LIKE '%uplink%' THEN a_device || ':' || a_port
         WHEN b_port LIKE '%uplink%' THEN b_device || ':' || b_port
         ELSE 'Both sides uplink'
       END AS uplink_port
FROM   netbox_cables
WHERE  (a_port LIKE '%uplink%' OR b_port LIKE '%uplink%')
  AND  cable_type NOT IN ('CAT6', 'Fibre');