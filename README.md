# ahkr-snyk

A repository to demonstrate competencies in the following areas:

* BASH Scripting
* CI/CD
* Python Module Development
* Docker Development
* Dynamic Client API Generation Development
* REST OpenAPI Consumption
* Custom API Consumption

## Scripts

### download-api-specs.sh

The script [download-api-specs.sh](./scripts/download-api-specs.sh) fetches latest Snyk API V1 and Snyk REST API specifications for later reference.

#### Snyk API V1

The script downloads the latest Snyk API V1 from: [https://snyk.docs.apiary.io/api-description-document](https://snyk.docs.apiary.io/api-description-document)

If the latest download does not yet exist, then the Markdown is saved with a date (YYYYMMDD format) prepended to the file extension. This allows archiving of previous versions for reference if needed.

If there is a new version found, it always replaces [api-description-document](./static/snyk-api/api-v1/api-description-document).

#### Snyk REST API

The script makes a request to the [OpenAPI endpoint](https://api.snyk.io/rest/openapi) to find all versions. A JSON filter is applied to only return production ready versions. The script then downloads and archives each production version if it does not already exist. This allows archiving and easier consumption of previous versions if needed.

## Static

| Path | Description |
|---|---|
| [./static/snyk-api/api-v1](./static/snyk-api/api-v1/) | Houses the Snyk API V1 Markdown specifications. The latest is always [api-description-document](./static/snyk-api/api-v1/api-description-document). |
| [./static/snyk-api/rest-api](./static/snyk-api/rest-api/) | Houses the Snyk REST OpenAPI specifications. |
