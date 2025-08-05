/* ───────────────────────────────────────────────
   Active NetBox cables that are NOT matched
   (potentially stale documentation)
   
   This finds cables marked as 'active' in NetBox but have no
   corresponding live LLDP neighbor relationship, suggesting
   the documentation may be outdated.
   ----------------------------------------------*/
SELECT nc.cable_id,
       nc.a_device,
       nc.a_port,
       nc.b_device,
       nc.b_port,
       nc.cable_type,
       nc.cable_status,
       nc.inserted_at
FROM   netbox_cables nc
WHERE  nc.cable_status = 'active'
  AND  nc.cable_id NOT IN (
        SELECT DISTINCT cable_id
        FROM comparison_results cr
        WHERE cr.match = 1
          AND cable_id IS NOT NULL
      );