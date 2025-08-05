/* ───────────────────────────────────────────────
   Ports that changed neighbor in the last 24 hours
   
   This identifies ports where the LLDP neighbor has changed
   recently, which could indicate network instability, cable
   moves, or equipment replacements.
   ----------------------------------------------*/
SELECT  hostname,
        local_port,
        COUNT(DISTINCT lldp_neighbor_device || ':' || lldp_neighbor_port) AS neighbor_changes,
        GROUP_CONCAT(DISTINCT lldp_neighbor_device || ':' || lldp_neighbor_port) AS all_neighbors,
        MIN(inserted_at) AS first_seen,
        MAX(inserted_at) AS last_seen
FROM    comparison_results
WHERE   inserted_at >= datetime('now','-1 day')
GROUP BY hostname, local_port
HAVING  COUNT(DISTINCT lldp_neighbor_device || ':' || lldp_neighbor_port) > 1
ORDER BY neighbor_changes DESC;