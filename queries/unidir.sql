/* ───────────────────────────────────────────────
   Unidirectional LLDP (A sees B, B doesn't see A)
   This finds cases where device A sees device B as a neighbor,
   but device B doesn't see device A back - indicating potential
   issues with LLDP configuration or connectivity problems.
   ----------------------------------------------*/
WITH lldp AS (
  SELECT hostname   AS dev_a,
         local_port AS port_a,
         neighbor_device AS dev_b,
         neighbor_port   AS port_b
  FROM switch_neighbors
)
SELECT a.dev_a AS device,
       a.port_a AS local_port,
       a.dev_b AS neighbor_device,
       a.port_b AS neighbor_port
FROM   lldp a
LEFT JOIN lldp b
  ON  a.dev_a  = b.dev_b
  AND a.port_a = b.port_b
  AND a.dev_b  = b.dev_a
  AND a.port_b = b.port_a
WHERE  b.dev_a IS NULL;