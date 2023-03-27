import xml.etree.ElementTree as ET
import csv
import json
from urllib.parse import urlparse
import sqlite3
import time
from datetime import datetime, timedelta

def log_event(event_type, **kwargs):
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    log_data = {
        "timestamp": now,
        "event_type": event_type,
        "event_data": kwargs
    }
    with open('issue_log.txt', 'a') as f:
        f.write(json.dumps(log_data) + '\n')

def friendly_time(time_str):
    time_parts = time_str.split('.')
    hours, minutes, seconds = time_parts[0].split(':')
    friendly_str = ''
    if int(hours) > 0:
        friendly_str += f'{int(hours)} hours, '
    if int(minutes) > 0:
        friendly_str += f'{int(minutes)} minutes, '
    friendly_str += f'{int(seconds)} seconds'
    return friendly_str

def get_substring(validation_location, validation_length, input_string):
    start = int(validation_location)
    end = start + int(validation_length)
    return input_string[start:end]

class Summary:
    def __init__(self, name, appscanversion, total_issues, total_variants, total_remediations, total_duration, hosts):
        self.name = name
        self.appscanversion = appscanversion
        self.total_issues = total_issues
        self.total_variants = total_variants
        self.total_remediations = total_remediations
        self.total_duration = total_duration
        self.hosts = hosts

    def to_csv(self, filename):
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['Name', 'AppScanInfo Version', 'Total Issues', 'Total Variants', 'Total Remediations', 'Total Duration'])
            writer.writerow([self.name, self.appscanversion, self.total_issues, self.total_variants, self.total_remediations, self.total_duration])
    
    def to_csv_hosts(self, filename):
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            writer.writerow(['URL', 'High Findings', 'Medium Findings', 'Low Findings'])
            for host in self.hosts:
                writer.writerow([host.url, host.total_high_findings, host.total_medium_findings, host.total_low_findings])

class Host:
    def __init__(self, url, total_high_findings, total_medium_findings, total_low_findings):
        self.url = url
        self.total_high_findings = total_high_findings
        self.total_medium_findings = total_medium_findings
        self.total_low_findings = total_low_findings

class RemediationType:
    def __init__(self, id, name, priority, recommendation_type, fix_recommendation):
        self.id = id
        self.name = name
        self.priority = priority
        self.recommendation_type = recommendation_type
        self.fix_recommendation = fix_recommendation

class IssueType:
    def __init__(self, id, remediation_id, advisory_id, advisory_name, advisory_test_description, threat, threat_ref, cause, risk, affected_products, cwe, refs, severity, invasive):
        self.id = id
        self.remediation_id = remediation_id
        self.advisory_id = advisory_id
        self.advisory_name = advisory_name
        self.advisory_test_description = advisory_test_description
        self.threat = threat
        self.threat_ref = threat_ref
        self.cause = cause
        self.risk = risk
        self.affected_products = affected_products
        self.cwe = cwe
        self.refs = refs
        self.severity = severity
        self.invasive = invasive

class Issue:
    def __init__(self, issue_type_id, is_noise, url, severity, cvss_base_score, cvss_base_vector, cvss_temporal_vector, cvss_env_factor, entity_name, entity_type, variant_difference, variant_reasoning, validation_location, validation_length, validation_string, original_traffic, test_traffic):
        self.issue_type_id = issue_type_id
        self.is_noise = is_noise
        self.url = url
        self.severity = severity
        self.cvss_base_score = cvss_base_score
        self.cvss_base_vector = cvss_base_vector
        self.cvss_temporal_vector = cvss_temporal_vector
        self.cvss_env_factor = cvss_env_factor
        self.entity_name = entity_name
        self.entity_type = entity_type
        self.variant_difference = variant_difference
        self.variant_reasoning = variant_reasoning
        self.validation_location = validation_location
        self.validation_length = validation_length
        self.validation_string = validation_string
        self.original_traffic = original_traffic
        self.test_traffic = test_traffic
        # parse URL to extract fully qualified domain name, port & hostname
        parsed_url = urlparse(url)
        fqdn = parsed_url.netloc
        if ':' in fqdn:
            self.fqdn = fqdn.split(':')[0]
        else:
            self.fqdn = fqdn
        hostname_parts = parsed_url.hostname.split(".")
        self.hostname = hostname_parts[0]
        if parsed_url.port:
            port = parsed_url.port
        else:
            if parsed_url.scheme == 'https':
                port = 443
            else:
                port = 80
        self.port = port
        self.protocol = parsed_url.scheme

    def get_advisory_name(self, issue_types):
        for issue_type in issue_types:
            if issue_type.id == self.issue_type_id:
                return issue_type.advisory_name
        return None
    
    def get_consolidated_proof(self):
        issue_dict = {
            "entity_name": self.entity_name,
            "entity_type": self.entity_type,
            "variant_difference": self.variant_difference,
            "variant_reasoning": self.variant_reasoning,
            "original_traffic": self.original_traffic,
            "test_traffic": self.test_traffic,
        }
        return json.dumps(issue_dict)
        # proof = ""
        # proof += f"Entity Name: {self.entity_name}\n"
        # proof += f"Entity Type: {self.entity_type}\n"
        # proof += f"Variant Difference: {self.variant_difference}\n"
        # proof += f"Variant Reasoning: {self.variant_reasoning}\n"
        # proof += f"Original Traffic: \n{self.original_traffic}\n"
        # proof += f"Test Traffic: \n{self.test_traffic}\n"
        # return proof

class Cookie:
    def __init__(self, name, value, url, domain, expires, secure):
        self.name = name
        self.value = value
        self.url = url
        self.domain = domain
        self.expires = expires
        self.secure = secure

class BrokenLink:
    def __init__(self, url, reason):
        self.url = url
        self.reason = reason

class FilteredLink:
    def __init__(self, url, reason):
        self.url = url
        self.reason = reason

class IssueStateTracker:
    def __init__(self, db_path):
        self.db_path = db_path
        self._create_remediation_table()
        self._create_issue_type_table()
        self._create_table()
        self._create_fp_table()
        self._create_issue_data_table()

    def _create_table(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS issues (
                id INTEGER PRIMARY KEY,
                issue_type_id TEXT,
                url TEXT,
                entity_name TEXT,
                entity_type TEXT,
                first_found INTEGER,
                last_found INTEGER,
                status TEXT,
                times_found INTEGER,
                FOREIGN KEY (issue_type_id) REFERENCES issue_types (id) ON DELETE SET NULL
            )
        """)
        conn.commit()
        conn.close()

    def _create_fp_table(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS false_positives (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue_id INTEGER UNIQUE,
                FOREIGN KEY (issue_id) REFERENCES issues (id)
            )
        """)
        conn.commit()
        conn.close()
    
    def _create_issue_type_table(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        # create issue_types table
        c.execute('''
            CREATE TABLE IF NOT EXISTS issue_types (
                id TEXT PRIMARY KEY,
                remediation_id TEXT,
                advisory_id TEXT,
                advisory_name TEXT,
                advisory_test_description TEXT,
                threat TEXT,
                threat_ref TEXT,
                cause TEXT,
                risk TEXT,
                affected_products TEXT,
                cwe TEXT,
                refs TEXT,
                severity TEXT,
                invasive TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (remediation_id) REFERENCES remediations (id) ON DELETE SET NULL
            )
        ''')
        conn.commit()
        conn.close()

    def _create_remediation_table(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS remediations (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                priority TEXT NOT NULL,
                recommendation_type TEXT NOT NULL,
                fix_recommendation TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        conn.close()

    def _create_issue_data_table(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS issue_data (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                is_noise TEXT,
                severity TEXT,
                cvss_base_score TEXT,
                cvss_base_vector TEXT,
                cvss_temporal_vector TEXT,
                cvss_env_factor TEXT,
                variant_difference TEXT,
                variant_reasoning TEXT,
                validation_location TEXT,
                validation_length INTEGER,
                validation_string TEXT,
                original_traffic TEXT,
                test_traffic TEXT,
                fqdn TEXT,
                hostname TEXT,
                port INTEGER,
                protocol TEXT,
                issue_id INTEGER,
                FOREIGN KEY (issue_id) REFERENCES issues(id)
            )
        """)
        conn.commit()
        conn.close()

    def track_issue(self, issue):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Check if issue already exists in the database
        c.execute("""
            SELECT id, times_found FROM issues
            WHERE issue_type_id = ? AND url = ? AND entity_name = ? AND entity_type = ?
        """, (issue.issue_type_id, issue.url, issue.entity_name, issue.entity_type))

        result = c.fetchone()
        if result is not None:
            issue_id, times_found = result
            # Update existing issue record
            c.execute("""
                UPDATE issues
                SET last_found = ?, times_found = ?,  status = 'open'
                WHERE id = ?
            """, (int(time.time()), times_found + 1, issue_id))
            log_event("updated_issue", id=issue_id, status="open")
        else:
            # Insert new issue record
            c.execute("""
                INSERT INTO issues
                (issue_type_id, url, entity_name, entity_type, first_found, last_found, status, times_found)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (issue.issue_type_id, issue.url, issue.entity_name, issue.entity_type, int(time.time()), int(time.time()), 'open', 1))
            log_event("inserted_issue", id=c.lastrowid, status="open", issue_id=issue.issue_type_id, url=issue.url, entity_name=issue.entity_name, entity_type=issue.entity_type)

        conn.commit()
        conn.close()

    def close_stale_issues(self, visited_urls):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Get unique netlocs from visited urls
        visited_netlocs = set([urlparse(url).netloc for url in visited_urls])
        # print(f"Visited netlocs: {visited_netlocs}")

        # Get open issues that are more than 1 day old and match a netloc
        stale_time = int(time.time()) - 86400 # 1 day in seconds
        c.execute("SELECT id FROM issues WHERE status = 'open' AND last_found < ?", (stale_time,))
        open_issues = c.fetchall()
        for issue_id in open_issues:
            c.execute("SELECT url FROM issues WHERE id = ?", (issue_id[0],))
            url = c.fetchone()[0]
            if urlparse(url).netloc in visited_netlocs:
                # Close stale issue
                c.execute("UPDATE issues SET status = 'fixed' WHERE id = ?", (issue_id[0],))
                # print(f"Closed ID: {issue_id}") 
                log_event("closed_issue", id=issue_id[0], status="fixed")
            

        conn.commit()
        conn.close()

    def check_issue_status(self, issue):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Check for issue in DB
        c.execute("""
            SELECT id, times_found FROM issues
            WHERE issue_type_id = ? AND url = ? AND entity_name = ? AND entity_type = ?
        """, (issue.issue_type_id, issue.url, issue.entity_name, issue.entity_type))

        # Fetch the first row of the query results
        result = c.fetchone()

        # Check if the issue is in the false positives table
        c.execute("SELECT * FROM false_positives WHERE id = ?", (result[0],))
        if c.fetchone() is not None:
            return "fixed"
        
        c.execute("""
            SELECT status FROM issues
            WHERE issue_type_id = ? AND url = ? AND entity_name = ? AND entity_type = ?
        """, (issue.issue_type_id, issue.url, issue.entity_name, issue.entity_type))

        result = c.fetchone()
        status = result[0] if result is not None else None

        conn.close()
        return status
    
    def upsert_issue_type(self, issue_type: IssueType):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Check if the issue type exists in the database
        c.execute("SELECT * FROM issue_types WHERE id = ?", (issue_type.id,))
        result = c.fetchone()

        # If the issue type does not exist, insert it
        if not result:
            values = (issue_type.id, issue_type.remediation_id, issue_type.advisory_id, issue_type.advisory_name,
                    issue_type.advisory_test_description, issue_type.threat, issue_type.threat_ref,
                    issue_type.cause, issue_type.risk, issue_type.affected_products, issue_type.cwe,
                    issue_type.refs, issue_type.severity, issue_type.invasive)
            c.execute("""INSERT INTO issue_types (id, remediation_id, advisory_id, advisory_name, advisory_test_description,
                                                threat, threat_ref, cause, risk, affected_products, cwe, refs,
                                                severity, invasive)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""", values)
            conn.commit()
            log_event("issue_type_added", id=issue_type.id, advisory_name=issue_type.advisory_name)
            # print(f"Issue type {issue_type.id} inserted into database.")
        else:
            # If issue type already exists, update all fields except for created_at
            c.execute("""
                UPDATE issue_types
                SET remediation_id=?, advisory_id=?, advisory_name=?, advisory_test_description=?,
                    threat=?, threat_ref=?, cause=?, risk=?, affected_products=?, cwe=?, refs=?,
                    severity=?, invasive=?, updated = CURRENT_TIMESTAMP
                WHERE id=?
            """, (issue_type.remediation_id, issue_type.advisory_id, issue_type.advisory_name,
                issue_type.advisory_test_description, issue_type.threat, issue_type.threat_ref,
                issue_type.cause, issue_type.risk, issue_type.affected_products, issue_type.cwe,
                issue_type.refs, issue_type.severity, issue_type.invasive, issue_type.id))
            conn.commit()
            log_event("issue_type_updated", id=issue_type.id, advisory_name=issue_type.advisory_name)
        conn.close()

    def upsert_remediation(self, remediation: RemediationType):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            SELECT id FROM remediations WHERE id = ?
        """, (remediation.id,))
        row = c.fetchone()
        
        if row is None:
            # Insert the remediation if it doesn't exist
            c.execute("""
                INSERT INTO remediations 
                (id, name, priority, recommendation_type, fix_recommendation)
                VALUES (?, ?, ?, ?, ?)
            """, (remediation.id, remediation.name, remediation.priority,
                remediation.recommendation_type, remediation.fix_recommendation))
            conn.commit()
            
            # Log the insert event
            log_event("remediation_added", id=remediation.id, name=remediation.name)
            # print(f"Inserted remediation {remediation.id}")
            
        else:
            # Update the remediation if it exists
            c.execute("""
                UPDATE remediations
                SET name = ?, priority = ?, recommendation_type = ?, 
                fix_recommendation = ?, updated = CURRENT_TIMESTAMP
                WHERE id = ?
            """, (remediation.name, remediation.priority, remediation.recommendation_type,
                remediation.fix_recommendation, remediation.id))
            conn.commit()
            
            # Log the update event
            log_event("remediation_updated", id=remediation.id, name=remediation.name)
            # print(f"Updated remediation {remediation.id}")
        conn.close()

    def upsert_issue_data(self, issue_data):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()

        # Check if issue already exists in the database
        c.execute("""
            SELECT id, times_found FROM issues
            WHERE issue_type_id = ? AND url = ? AND entity_name = ? AND entity_type = ?
        """, (issue_data.issue_type_id, issue_data.url, issue_data.entity_name, issue_data.entity_type))

        issue_id_result = c.fetchone()
        if issue_id_result is not None:
            # Check if issue_data already exists in the database
            c.execute("""
                SELECT id FROM issue_data
                WHERE id = ?
            """, (issue_id_result[0],))
            row = c.fetchone()
        
            if row is None:
                # Issue data doesn't exist, insert a new row
                c.execute("""
                    INSERT INTO issue_data (id, is_noise, severity, cvss_base_score, cvss_base_vector, cvss_temporal_vector, cvss_env_factor, variant_difference, variant_reasoning, validation_location, validation_length, validation_string, original_traffic, test_traffic, fqdn, hostname, port, protocol)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (issue_id_result[0], issue_data.is_noise, issue_data.severity, issue_data.cvss_base_score, issue_data.cvss_base_vector, issue_data.cvss_temporal_vector, issue_data.cvss_env_factor, issue_data.variant_difference, issue_data.variant_reasoning, issue_data.validation_location, issue_data.validation_length, issue_data.validation_string, issue_data.original_traffic, issue_data.test_traffic, issue_data.fqdn, issue_data.hostname, issue_data.port, issue_data.protocol))
            else:
                # Issue data exists, update the row
                c.execute("""
                    UPDATE issue_data SET is_noise = ?, severity = ?, cvss_base_score = ?, cvss_base_vector = ?, cvss_temporal_vector = ?, cvss_env_factor = ?, variant_difference = ?, variant_reasoning = ?, validation_location = ?, validation_length = ?, validation_string = ?, original_traffic = ?, test_traffic = ?, fqdn = ?, hostname = ?, port = ?, protocol = ?
                    WHERE id = ?
                """, (issue_data.is_noise, issue_data.severity, issue_data.cvss_base_score, issue_data.cvss_base_vector, issue_data.cvss_temporal_vector, issue_data.cvss_env_factor, issue_data.variant_difference, issue_data.variant_reasoning, issue_data.validation_location, issue_data.validation_length, issue_data.validation_string, issue_data.original_traffic, issue_data.test_traffic, issue_data.fqdn, issue_data.hostname, issue_data.port, issue_data.protocol, issue_data.id))
            
        conn.commit()
        conn.close()

def parse_summary(root):
    # Parse Summary Data
    name = root.attrib['Name']
    app_scan_info_version = root.find('.//AppScanInfo/Version').text
    total_issues = root.find('.//Summary/TotalIssues').text
    total_variants = root.find('.//Summary/TotalVariants').text
    total_remediations = root.find('.//Summary/TotalRemediations').text
    total_duration = friendly_time(root.find('.//Summary/TotalScanDuration').text)

    hosts = []
    for host in root.findall('.//Summary/Hosts/Host'):
        url = host.get('Name')
        high_findings = host.find('TotalHighSeverityIssues').text
        medium_findings = host.find('TotalMediumSeverityIssues').text
        low_findings = host.find('TotalLowSeverityIssues').text
        hosts.append(Host(url, high_findings, medium_findings, low_findings))
        
    return Summary(name, app_scan_info_version, total_issues, total_variants, total_remediations, total_duration, hosts)

def parse_remediations(root):
    remediations = []
    for remediation_type in root.findall('.//RemediationTypes/RemediationType'):
        remediation_id = remediation_type.attrib['ID']
        name = remediation_type.find('Name').text
        priority = remediation_type.find('Priority').text
        type = remediation_type.find('fixRecommendation').attrib['type']
        fix_recommendation = remediation_type.find('fixRecommendation')
        # concatenate the text elements into a paragraph
        fix_paragraph = ''
        for element in fix_recommendation:
            if element.tag == "text" and element.text != None:
                fix_paragraph += element.text.strip() + "\n"
            elif element.tag == "link":
                fix_paragraph += element.text.strip() + " (" + element.attrib["target"] + ")\n"
        remediations.append(RemediationType(remediation_id, name, priority, type, fix_paragraph))
    return remediations

def parse_issue_types(root):
    issue_types_data = []
    for issue_type in root.findall('.//IssueTypes/IssueType'):
        id = issue_type.attrib['ID']
        remediation_id = issue_type.find('RemediationID').text
        advisory_id = issue_type.find('advisory/id').text
        advisory_name = issue_type.find('advisory/name').text
        advisory_test_description = issue_type.find('advisory/testDescription').text
        threat = issue_type.find('advisory/threatClassification/name').text
        threat_ref = issue_type.find('advisory/threatClassification/reference').text
        cause = issue_type.find('advisory/causes/cause').text
        
        risks = issue_type.find('advisory/securityRisks')
        # create risk paragraph
        risk = ''
        for line in risks:
            if line.tag == "text" and line.text != None:
                risk += line.text.strip() + "\n"
            elif line.tag == "link":
                risk += line.text.strip() + " (" + line.attrib["target"] + ")\n"

        affected_products = issue_type.find('advisory/affectedProducts/text').text
        cwe = issue_type.find('advisory/cwe/link').attrib['id']
        
        ref_list = issue_type.find('advisory/references')
        refs = ''
        for ref in ref_list:
            if ref.tag == "text" and line.text != None:
                refs += ref.text.strip() + "\n"
            elif ref.tag == "link":
                refs += ref.text.strip() + " (" + ref.attrib["target"] + ")\n"

        severity = issue_type.find('Severity').text
        invasive = issue_type.find('Invasive').text

        issue_types_data.append(IssueType(id, remediation_id, advisory_id, advisory_name, advisory_test_description, threat, threat_ref, cause, risk, affected_products, cwe, refs, severity, invasive))
    return issue_types_data

def parse_issues(root):
    issues_data = []
    for issue in root.findall('.//Issues/Issue'):
        issue_type_id = issue.attrib['IssueTypeID']
        is_noise = issue.attrib['Noise']
        url = issue.find('Url').text
        severity = issue.find('Severity').text
        cvss_base_score = issue.find('CVSS/Score').text
        cvss_base_vector = issue.find('CVSS/BaseVector').text
        cvss_temporal_vector = issue.find('CVSS/TemporalVector').text
        cvss_env_factor = issue.find('CVSS/EnvironmentalVector').text
        entity_name = issue.find('Entity').attrib['Name']
        entity_type = issue.find('Entity').attrib['Type']
        variant_difference = issue.find('Variant/Difference').text
        variant_reasoning = issue.find('Variant/Reasoning').text
        validation_location = issue.find('Variant/ValidationDataLocationAtTestResponse/Validation').attrib['Location']
        validation_length = issue.find('Variant/ValidationDataLocationAtTestResponse/Validation').attrib['Length']
        validation_string = issue.find('Variant/ValidationDataLocationAtTestResponse/Validation').attrib['String']
        original_traffic = issue.find('Variant/OriginalHttpTraffic').text
        test_traffic = issue.find('Variant/TestHttpTraffic').text
        issues_data.append(Issue(issue_type_id, is_noise, url, severity, cvss_base_score, cvss_base_vector, cvss_temporal_vector, cvss_env_factor, entity_name, entity_type, variant_difference, variant_reasoning, validation_location, validation_length, validation_string, original_traffic, test_traffic))
    return issues_data

def parse_cookies(root):
    cookies_data = []
    for cookie in root.findall('.//Cookies/Cookie'):
        name = cookie.get('name')
        value = cookie.get('value')
        url = cookie.get('url')
        domain = cookie.get('domain')
        expires = cookie.get('expires')
        secure = cookie.get('secure')
        cookies_data.append(Cookie(name, value, url, domain, expires, secure))
    return cookies_data

def parse_visited_links(root):
    visited_links_data = []
    for visited_link in root.findall('.//VisitedLinks/VisitedLink'):
        url = visited_link.find('Url').text
        visited_links_data.append(url)
    return visited_links_data

def parse_broken_links(root):
    broken_links_data = []
    for broken_link in root.findall('.//BrokenLinks/BrokenLink'):
        url = broken_link.find('Url').text
        reason = broken_link.find('Reason').text
        broken_links_data.append(FilteredLink(url, reason))
    return broken_links_data

def parse_filtered_links(root):
    filtered_links_data = []
    for filtered_link in root.findall('.//FilteredLinks/FilteredLink'):
        url = filtered_link.find('Url').text
        reason = filtered_link.find('Reason').text
        filtered_links_data.append(FilteredLink(url, reason))
    return filtered_links_data

def snow_csv_export(remediations, issue_types, issues, tracker):
    with open('./csvs/snow_manual_ingest.csv', mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['asset_id','mac_address','fqdn','netbios','ip_address','hostname','vulnerability_id','vulnerability_summary','severity','port','protocol','proof','state'])
        for issue in issues:
            # print(tracker.check_issue_status(issue))
            writer.writerow([None, None, issue.fqdn, issue.hostname, None, issue.hostname, issue.issue_type_id, issue.get_advisory_name(issue_types), issue.severity, issue.port, issue.protocol, issue.get_consolidated_proof(), tracker.check_issue_status(issue)])

# Open the XML file
tree = ET.parse('input.xml')
root = tree.getroot()

# Parse summary Portion
summary = parse_summary(root)

# output to csv
summary.to_csv("./csvs/summary.csv")
summary.to_csv_hosts("./csvs/summary_hosts.csv")

# parse and return remediations
remediations = parse_remediations(root)

# output remediations to csv
with open("./csvs/remediations.csv", 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Remediation ID', 'Name', 'Priority', 'Remediation Type', 'Fix Recommendation'])
    for remediation in remediations:
        writer.writerow([remediation.id, remediation.name, remediation.priority, remediation.recommendation_type, remediation.fix_recommendation])

# parse and return Issue Types
issue_types = parse_issue_types(root)
with open("./csvs/issue_types.csv", 'w', newline='') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Issue ID', 'Remediation ID', 'Advisory ID', 'Advisory Name', 'Advisory Test Description', 'Threat', 'Threat Reference', 'Cause', 'Risk', 'Affected Products', 'CWE', 'References', 'Severity', 'Invasive Test'])
    for issue_type in issue_types:
        writer.writerow([issue_type.id, issue_type.remediation_id, issue_type.advisory_id, issue_type.advisory_name, issue_type.advisory_test_description, issue_type.threat, issue_type.threat_ref, issue_type.cause, issue_type.risk, issue_type.affected_products, issue_type.cwe, issue_type.refs, issue_type.severity, issue_type.invasive])

# parse and return issues
issues = parse_issues(root)
with open('./csvs/issues.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Issue Type ID', 'Is Noise', 'URL', 'Severity', 'CVSS Base', 'CVSS Base Vector', 'CVSS Temporal Vector', 'CVSS Environment Factor', 'Entity Name', 'Entity Type', 'Variant Difference', 'Variant Reasoning', 'Validation Location', 'Validation Length', 'Validation String', 'Original Traffic', 'Test Traffic'])
    for issue in issues:
        writer.writerow([issue.issue_type_id, issue.is_noise, issue.url, issue.severity, issue.cvss_base_score, issue.cvss_base_vector, issue.cvss_temporal_vector, issue.cvss_env_factor, issue.entity_name, issue.entity_type, issue.variant_difference, issue.variant_reasoning, issue.validation_location, issue.validation_length, issue.validation_string, issue.original_traffic, issue.test_traffic])
        # print(get_substring(issue.validation_location, issue.validation_length, issue.test_traffic))  # Output: "is"

# parse cookies (TODO)
# cookies = parse_cookies(root)

# parse visited links
visited_links = parse_visited_links(root)
with open('./csvs/visited_links.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Visited URL'])
    for link in visited_links:
        writer.writerow([link])

broken_links = parse_broken_links(root)
with open('./csvs/broken_links.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Broken URL', 'Reason'])
    for link in broken_links:
        writer.writerow([link.url, link.reason])

filtered_links = parse_filtered_links(root)
with open('./csvs/filtered_links.csv', mode='w', newline='') as file:
    writer = csv.writer(file)
    writer.writerow(['Filtered URL', 'Reason'])
    for link in filtered_links:
        writer.writerow([link.url, link.reason])

# init issue database and update issue tracking
tracker = IssueStateTracker('./issues.db')

# upsert issues into db table
for issue_type in issue_types:
    tracker.upsert_issue_type(issue_type)

# upsert remediations into db table
for remediation in remediations:
    tracker.upsert_remediation(remediation)

# update issues
for issue in issues:
    tracker.track_issue(issue)
    tracker.upsert_issue_data(issue)

# close issues in visited domains that weren't scanned in the last day
tracker.close_stale_issues(visited_links)

snow_csv_export(remediations, issue_types, issues, tracker)

print('Parsing complete!')



