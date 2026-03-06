# API Endpoints

## Base URL

Default: `https://api.crowdstrike.com`

Configurable via `FALCON_BASE_URL` or `--base-url`.

## Security Operations

### Hosts (`host`)
- List: GET `/devices/queries/devices/v1`
- Get: GET `/devices/entities/devices/v2`

### Detections (`detection`)
- List: GET `/detects/queries/detects/v1`
- Get: POST `/detects/entities/summaries/GET/v1`

### Incidents (`incident`)
- List: GET `/incidents/queries/incidents/v1`
- Get: POST `/incidents/entities/incidents/GET/v1`

### Alerts (`alert`)
- List: GET `/alerts/queries/alerts/v2`
- Get: POST `/alerts/entities/alerts/v2`

### Quarantine (`quarantine`)
- List: GET `/quarantine/queries/quarantined-files/v1`
- Get: POST `/quarantine/entities/quarantined-files/GET/v1`

### Real Time Response (`rtr`)
- List: GET `/real-time-response/queries/sessions/v1`
- Get: POST `/real-time-response/entities/sessions/GET/v1`

### Real Time Response Admin (`rtr-admin`)
- List: GET `/real-time-response/queries/put-files/v1`
- Get: GET `/real-time-response/entities/put-files/v2`

### Real Time Response Audit (`rtr-audit`)
- List: GET `/real-time-response-audit/combined/sessions/v1`

## Policies

### Prevention Policies (`prevention-policy`)
- List: GET `/policy/queries/prevention/v1`
- Get: GET `/policy/entities/prevention/v1`

### Device Control Policies (`device-control-policy`)
- List: GET `/policy/queries/device-control/v1`
- Get: GET `/policy/entities/device-control/v1`

### Firewall Policies (`firewall-policy`)
- List: GET `/policy/queries/firewall/v1`
- Get: GET `/policy/entities/firewall/v1`

### Sensor Update Policies (`sensor-update-policy`)
- List: GET `/policy/queries/sensor-update/v1`
- Get: GET `/policy/entities/sensor-update/v2`

### Response Policies (`response-policy`)
- List: GET `/policy/queries/response/v1`
- Get: GET `/policy/entities/response/v1`

### Content Update Policies (`content-update-policy`)
- List: GET `/policy/queries/content-update/v1`
- Get: GET `/policy/entities/content-update/v1`

### IOA Exclusions (`ioa-exclusion`)
- List: GET `/policy/queries/ioa-exclusions/v1`
- Get: GET `/policy/entities/ioa-exclusions/v1`

## Threat Intelligence

### Intel (`intel`)
- List: GET `/intel/queries/actors/v1`
- Get: GET `/intel/entities/actors/v1`

### Intel Feeds (`intel-feed`)
- List: GET `/intel/queries/feeds/v1`
- Get: GET `/intel/entities/feeds/v1`

### Intel Indicator Graph (`intel-graph`)
- List: GET `/intel/queries/indicator-graph/v1`
- Get: GET `/intel/entities/indicator-graph/v1`

### IOC (`ioc`)
- List: GET `/iocs/queries/indicators/v1`
- Get: GET `/iocs/entities/indicators/v1`

### IOCs Legacy (`iocs`)
- List: GET `/indicators/queries/iocs/v1`
- Get: GET `/indicators/entities/iocs/v1`

### Custom IOA (`custom-ioa`)
- List: GET `/ioarules/queries/rules/v1`
- Get: GET `/ioarules/entities/rules/v1`

### MalQuery (`malquery`)
- List: GET `/malquery/queries/exact-search/v1`
- Get: GET `/malquery/entities/requests/v1`

### Falcon Intelligence Sandbox (`sandbox`)
- List: GET `/falconx/queries/submissions/v1`
- Get: GET `/falconx/entities/submissions/v1`

### Recon (`recon`)
- List: GET `/recon/queries/rules/v1`
- Get: GET `/recon/entities/rules/v1`

### Tailored Intelligence (`tailored-intel`)
- List: GET `/ti/queries/reports/v1`
- Get: GET `/ti/entities/reports/v1`

## Host Management

### Host Groups (`host-group`)
- List: GET `/devices/queries/host-groups/v1`
- Get: GET `/devices/entities/host-groups/v1`

### Host Migration (`host-migration`)
- List: GET `/host-migration/queries/migrations/v1`
- Get: GET `/host-migration/entities/migrations/v1`

### Sensor Download (`sensor-download`)
- List: GET `/sensors/queries/installers/v2`
- Get: GET `/sensors/entities/installers/v2`

### Sensor Usage (`sensor-usage`)
- Get: GET `/billing-dashboards-usage/aggregates/weekly-average/v1`

### Sensor Visibility Exclusions (`sv-exclusion`)
- List: GET `/policy/queries/sv-exclusions/v1`
- Get: GET `/policy/entities/sv-exclusions/v1`

### ML Exclusions (`ml-exclusion`)
- List: GET `/policy/queries/ml-exclusions/v1`
- Get: GET `/policy/entities/ml-exclusions/v1`

### Installation Tokens (`install-token`)
- List: GET `/installation-tokens/queries/tokens/v1`
- Get: GET `/installation-tokens/entities/tokens/v1`

## Cloud Security

### Cloud AWS Registration (`cloud-aws`)
- List: GET `/cloud-connect-cspm-aws/queries/account/v1`
- Get: GET `/cloud-connect-cspm-aws/entities/account/v1`

### Cloud Azure Registration (`cloud-azure`)
- List: GET `/cloud-connect-cspm-azure/queries/account/v1`
- Get: GET `/cloud-connect-cspm-azure/entities/account/v1`

### Cloud GCP Registration (`cloud-gcp`)
- List: GET `/cloud-connect-cspm-gcp/queries/account/v1`
- Get: GET `/cloud-connect-cspm-gcp/entities/account/v1`

### Cloud OCI Registration (`cloud-oci`)
- List: GET `/cloud-connect-oci/queries/account/v1`
- Get: GET `/cloud-connect-oci/entities/account/v1`

### Cloud Connect AWS (`cloud-connect-aws`)
- List: GET `/cloud-connect-aws/queries/accounts/v1`
- Get: GET `/cloud-connect-aws/entities/accounts/v1`

### Cloud Policies (`cloud-policy`)
- List: GET `/settings/queries/policy/v1`
- Get: GET `/settings/entities/policy-details/v2`

### Cloud Security (`cloud-security`)
- List: GET `/cloud-security/queries/resources/v1`
- Get: GET `/cloud-security/entities/resources/v1`

### Cloud Security Assets (`cloud-asset`)
- List: GET `/cloud-security-assets/queries/resources/v1`
- Get: GET `/cloud-security-assets/entities/resources/v1`

### Cloud Security Compliance (`cloud-compliance`)
- List: GET `/cloud-security-compliance/queries/scan-schedule/v1`
- Get: GET `/cloud-security-compliance/entities/scan-schedule/v1`

### Cloud Security Detections (`cloud-detection`)
- List: GET `/cloud-security-detections/queries/alerts/v1`
- Get: GET `/cloud-security-detections/entities/alerts/v1`

### Cloud Snapshots (`cloud-snapshot`)
- List: GET `/snapshots/queries/deployments/v1`
- Get: GET `/snapshots/entities/deployments/v1`

### CSPM Registration (`cspm`)
- List: GET `/cspm/queries/policy-settings/v1`
- Get: GET `/cspm/entities/policy-settings/v1`

### D4C Registration (`d4c`)
- List: GET `/d4c-registration/queries/accounts/v1`
- Get: GET `/d4c-registration/entities/accounts/v1`

### Configuration Assessment (`config-assessment`)
- List: GET `/configuration-assessment/queries/assessments/v1`
- Get: GET `/configuration-assessment/entities/assessments/v1`

## Container Security

### Container Alerts (`container-alert`)
- List: GET `/container-security/queries/alerts/v1`
- Get: GET `/container-security/entities/alerts/v1`

### Container Detections (`container-detection`)
- List: GET `/container-security/queries/detections/v1`
- Get: GET `/container-security/entities/detections/v1`

### Container Images (`container-image`)
- List: GET `/container-security/queries/images/v1`
- Get: GET `/container-security/entities/images/v1`

### Container Image Compliance (`container-compliance`)
- List: GET `/container-compliance/queries/compliance/v1`
- Get: GET `/container-compliance/entities/compliance/v1`

### Container Packages (`container-package`)
- List: GET `/container-security/queries/packages/v1`
- Get: GET `/container-security/entities/packages/v1`

### Container Vulnerabilities (`container-vuln`)
- List: GET `/container-security/queries/vulnerabilities/v1`
- Get: GET `/container-security/entities/vulnerabilities/v1`

### Falcon Container (`falcon-container`)
- List: GET `/container-security/queries/falcon-images/v1`
- Get: GET `/container-security/entities/falcon-images/v1`

### Kubernetes Protection (`k8s`)
- List: GET `/container-security/queries/kubernetes/clusters/v1`
- Get: GET `/container-security/entities/kubernetes/clusters/v1`

### Kubernetes Container Compliance (`k8s-compliance`)
- List: GET `/container-compliance/queries/kubernetes/compliance/v1`
- Get: GET `/container-compliance/entities/kubernetes/compliance/v1`

## Vulnerability Management

### Spotlight Vulnerabilities (`spotlight-vuln`)
- List: GET `/spotlight/queries/vulnerabilities/v1`
- Get: GET `/spotlight/entities/vulnerabilities/v2`

### Spotlight Evaluation Logic (`spotlight-eval`)
- List: GET `/spotlight/queries/evaluation-logic/v1`
- Get: GET `/spotlight/entities/evaluation-logic/v1`

### Spotlight Vulnerability Metadata (`spotlight-metadata`)
- List: GET `/spotlight/queries/vulnerability-metadata/v1`
- Get: GET `/spotlight/entities/vulnerability-metadata/v1`

### Exposure Management (`exposure`)
- List: GET `/fem/queries/external-assets/v1`
- Get: GET `/fem/entities/external-assets/v1`

### Serverless Vulnerabilities (`serverless-vuln`)
- List: GET `/serverless-vulnerabilities/queries/deployments/v1`
- Get: GET `/serverless-vulnerabilities/entities/deployments/v1`

### Drift Indicators (`drift`)
- List: GET `/container-security/queries/drift-indicators/v1`
- Get: GET `/container-security/entities/drift-indicators/v1`

### Unidentified Containers (`unidentified-container`)
- List: GET `/container-security/queries/unidentified-containers/v1`
- Get: GET `/container-security/entities/unidentified-containers/v1`

### Image Assessment Policies (`image-policy`)
- List: GET `/image-assessment-policies/queries/policies/v1`
- Get: GET `/image-assessment-policies/entities/policies/v1`

### Configuration Assessment Evaluation Logic (`config-eval`)
- List: GET `/configuration-assessment/queries/evaluation-logic/v1`
- Get: GET `/configuration-assessment/entities/evaluation-logic/v1`

## Monitoring

### Event Streams (`event-stream`)
- List: GET `/sensors/queries/data-feed/v1`
- Get: GET `/sensors/entities/data-feed/v1`

### Falcon Complete Dashboard (`falcon-complete`)
- List: GET `/falcon-complete-dashboards/queries/allowlist/v1`
- Get: GET `/falcon-complete-dashboards/entities/allowlist/v1`

### OverWatch Dashboard (`overwatch`)
- Get: POST `/overwatch-dashboards/aggregates/events/GET/v1`

### FileVantage (`filevantage`)
- List: GET `/filevantage/queries/policies/v1`
- Get: GET `/filevantage/entities/policies/v1`

### Firewall Management (`firewall`)
- List: GET `/fwmgr/queries/rules/v1`
- Get: GET `/fwmgr/entities/rules/v1`

### Discover (`discover`)
- List: GET `/discover/queries/hosts/v1`
- Get: GET `/discover/entities/hosts/v1`

### Identity Protection (`identity`)
- List: GET `/identity-protection/queries/entities/v1`
- Get: GET `/identity-protection/entities/entities/v1`

### Zero Trust Assessment (`zero-trust`)
- Get: GET `/zero-trust-assessment/entities/assessments/v1`

### ThreatGraph (`threatgraph`)
- List: GET `/threatgraph/queries/edge-types/v1`
- Get: GET `/threatgraph/entities/vertices/v1`

## Administration

### User Management (`user`)
- List: GET `/user-management/queries/users/v1`
- Get: POST `/user-management/entities/users/GET/v1`

### OAuth2 (`oauth2`)
- List: GET `/oauth2/queries/tokens/v1`

### MSSP (`mssp`)
- List: GET `/mssp/queries/children/v1`
- Get: GET `/mssp/entities/children/v1`

### Message Center (`message`)
- List: GET `/message-center/queries/case-activities/v1`
- Get: GET `/message-center/entities/case-activities/v1`

### Case Management (`case`)
- List: GET `/message-center/queries/cases/v1`
- Get: POST `/message-center/entities/cases/GET/v1`

### Workflows (`workflow`)
- List: GET `/workflows/queries/definitions/v1`
- Get: GET `/workflows/entities/definitions/v1`

### Scheduled Reports (`scheduled-report`)
- List: GET `/reports/queries/scheduled-reports/v1`
- Get: GET `/reports/entities/scheduled-reports/v1`

### Report Executions (`report-execution`)
- List: GET `/reports/queries/report-executions/v1`
- Get: GET `/reports/entities/report-executions/v1`

### Device Content (`device-content`)
- List: GET `/device-content/queries/policies/v1`
- Get: GET `/device-content/entities/policies/v1`

### Deployments (`deployment`)
- List: GET `/deployment-coordinator/queries/deployments/v1`
- Get: GET `/deployment-coordinator/entities/deployments/v1`

### Delivery Settings (`delivery-setting`)
- Get: GET `/delivery-settings/entities/delivery-settings/v1`

### Data Protection (`data-protection`)
- List: GET `/data-protection/queries/configurations/v1`
- Get: GET `/data-protection/entities/configurations/v1`

### Certificate-Based Exclusions (`cert-exclusion`)
- List: GET `/exclusions/queries/certificates/v1`
- Get: GET `/exclusions/entities/certificates/v1`

## Other

### API Integrations (`api-integration`)
- List: GET `/api-integrations/queries/integrations/v1`
- Get: GET `/api-integrations/entities/integrations/v1`

### ASPM (`aspm`)
- List: GET `/aspm-api-gateway/queries/services/v1`
- Get: GET `/aspm-api-gateway/entities/services/v1`

### CAO Hunting (`cao-hunting`)
- List: GET `/cao/queries/hunting/v1`
- Get: GET `/cao/entities/hunting/v1`

### Correlation Rules (`correlation-rule`)
- List: GET `/correlation-rules/queries/rules/v1`
- Get: GET `/correlation-rules/entities/rules/v1`

### Correlation Rules Admin (`correlation-admin`)
- List: GET `/correlation-rules/queries/rules/v1`
- Get: GET `/correlation-rules/entities/rules/v1`

### Custom Storage (`custom-storage`)
- List: GET `/custom-storage/queries/objects/v1`
- Get: GET `/custom-storage/entities/objects/v1`

### DataScanner (`datascanner`)
- List: GET `/data-security-dspm/queries/scans/v1`
- Get: GET `/data-security-dspm/entities/scans/v1`

### Downloads (`download`)
- List: GET `/csdownloads/queries/files/v1`
- Get: GET `/csdownloads/entities/files/v1`

### FaaS Executions (`faas`)
- List: GET `/faas/queries/executions/v1`
- Get: GET `/faas/entities/executions/v1`

### FDR (`fdr`)
- List: GET `/fdr/queries/schema-fields/v1`
- Get: GET `/fdr/entities/schema-fields/v1`

### Foundry LogScale (`logscale`)
- List: GET `/loggingapi/queries/saved-searches/v1`
- Get: GET `/loggingapi/entities/saved-searches/v1`

### IT Automation (`it-automation`)
- List: GET `/it-automation/queries/policies/v1`
- Get: GET `/it-automation/entities/policies/v1`

### Mobile Enrollment (`mobile`)
- List: GET `/enrollments/queries/mobile-enrollments/v4`
- Get: GET `/enrollments/entities/details/v4`

### NGSIEM (`ngsiem`)
- List: GET `/ngsiem/queries/rules/v1`
- Get: GET `/ngsiem/entities/rules/v1`

### On-Demand Scans (`ods`)
- List: GET `/ods/queries/scans/v1`
- Get: GET `/ods/entities/scans/v1`

### Quick Scan (`quick-scan`)
- List: GET `/scanner/queries/scans/v1`
- Get: GET `/scanner/entities/scans/v1`

### Quick Scan Pro (`quick-scan-pro`)
- List: GET `/quickscanpro/queries/scans/v1`
- Get: GET `/quickscanpro/entities/scans/v1`

### SaaS Security (`saas-security`)
- List: GET `/saas-security/queries/deployments/v1`
- Get: GET `/saas-security/entities/deployments/v1`

### Sample Uploads (`sample`)
- List: GET `/samples/queries/samples/GET/v1`
- Get: GET `/samples/entities/samples/v3`
