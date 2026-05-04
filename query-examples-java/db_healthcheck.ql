/**
 * @name Database Health Check
 * @description Minimal query to verify a CodeQL Java database can be analyzed.
 * @kind problem
 * @id vulnsynth/db-healthcheck
 * @problem.severity warning
 */

import java

from RefType t
where t.getName() = "Object"
select t, "ok"