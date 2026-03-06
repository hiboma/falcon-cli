# API Endpoints

## Base URL

Default: `https://api.crowdstrike.com`

Configurable via `FALCON_BASE_URL` or `--base-url`.

## Hosts

### Query Host IDs

- Method: GET
- Path: `/devices/queries/devices/v1`
- Parameters:
  - `filter` (string, optional) - FQL filter
  - `limit` (integer, optional) - Max results (default: 100)
  - `offset` (string, optional) - Pagination offset

### Get Host Details

- Method: GET
- Path: `/devices/entities/devices/v2`
- Parameters:
  - `ids` (string[], required) - Host AIDs

## Detections

### Query Detection IDs

- Method: GET
- Path: `/detects/queries/detects/v1`
- Parameters:
  - `filter` (string, optional) - FQL filter
  - `limit` (integer, optional) - Max results (default: 100)
  - `offset` (string, optional) - Pagination offset

### Get Detection Summaries

- Method: GET
- Path: `/detects/entities/summaries/GET/v1`
- Parameters:
  - `ids` (string[], required) - Detection IDs
