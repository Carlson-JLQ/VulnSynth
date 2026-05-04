chroma run --path chroma_db --host 0.0.0.0 --port 8000



Error fetching https://codeql.github.com/codeql-standard-libraries/java/semmle/code/java/Member.qll/predicate.Member$Field$getKotlinType.0.html: 503 Server Error: Service Unavailable for url: https://codeql.github.com/codeql-standard-libraries/java/semmle/code/java/Member.qll/predicate.Member$Field$getKotlinType.0.html



Error fetching https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/models/interfaces/Sql.qll/predicate.Sql$SqlExecutionFunction$hasSqlArgument.1.html: 503 Server Error: Service Unavailable for url: https://codeql.github.com/codeql-standard-libraries/cpp/semmle/code/cpp/models/interfaces/Sql.qll/predicate.Sql$SqlExecutionFunction$hasSqlArgument.1.html


我的目标是从cve id出发
现在的实现进度，plan agent从cve id生成了L1,L2,L3产物，然后genAgent根据L3先生成片段，再合成完整的query



CVE-2025-27818