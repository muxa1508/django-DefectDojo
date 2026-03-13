from dojo.models import Finding, Endpoint


class WazuhV4_8:
    def parse_findings(self, test, data):
        dupes = {}
        vulnerabilities = data.get("hits", {}).get("hits", [])
        for item_source in vulnerabilities:
            item = item_source.get("_source")
            vuln = item.get("vulnerability")
            cve = vuln.get("id")

            # Unique key should be only CVE (not including agent)
            dupe_key = cve

            agent_name = item.get("agent").get("name")

            description = vuln.get("description")
            severity = vuln.get("severity")
            cvssv3_score = vuln.get("score").get("base") if vuln.get("score") else None
            publish_date = vuln.get("published_at").split("T")[0]
            detection_time = vuln.get("detected_at").split("T")[0]
            references = vuln.get("reference")

            # Map Wazuh severity to its equivalent in DefectDojo
            SEVERITY_MAP = {
                "Critical": "Critical",
                "High": "High",
                "Medium": "Medium",
                "Low": "Low",
                "Info": "Info",
                "Informational": "Info",
                "Untriaged": "Info",
            }
            severity = SEVERITY_MAP.get(severity, "Info")

            title = (
                cve + " affects (version: " + item.get("package").get("version") + ")"
            )

            if dupe_key not in dupes:
                # First occurrence of this CVE - create new Finding
                find = Finding(
                    title=title,
                    test=test,
                    description=description,
                    severity=severity,
                    references=references,
                    static_finding=True,
                    component_name=item.get("package").get("name"),
                    component_version=item.get("package").get("version"),
                    cvssv3_score=cvssv3_score,
                    publish_date=publish_date,
                    unique_id_from_tool=dupe_key,
                    date=detection_time,
                )
                
                if agent_name:
                    find.unsaved_endpoints = [Endpoint(host=agent_name)]

                find.unsaved_vulnerability_ids = [cve]
                dupes[dupe_key] = find
            else:
                # CVE already exists - add new endpoint to existing Finding
                find = dupes[dupe_key]
                
                # Add endpoint
                if agent_name:
                    new_endpoint = Endpoint(host=agent_name)
                    if hasattr(find, 'unsaved_endpoints'):
                        find.unsaved_endpoints.append(new_endpoint)
                    else:
                        find.unsaved_endpoints = [new_endpoint]

        return list(dupes.values())