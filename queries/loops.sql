/* ───────────────────────────────────────────────
   "Too many neighbors" – possible loops or misconfigurations
   
   This finds switch ports that have multiple LLDP neighbors,
   which could indicate network loops, port aggregation issues,
   or LLDP misconfigurations.
   ----------------------------------------------*/
SELECT hostname,
       local_port,
       COUNT(*) AS neighbor_count,
       GROUP_CONCAT(neighbor_device || ':' || neighbor_port) AS all_neighbors,
       GROUP_CONCAT(DISTINCT capability) AS capabilities
FROM   switch_neighbors
GROUP  BY hostname, local_port
HAVING neighbor_count > 1
ORDER BY neighbor_count DESC;