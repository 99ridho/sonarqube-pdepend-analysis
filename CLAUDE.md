# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This repository contains two Python analysis scripts for PHP code quality assessment, designed to generate research paper sections:

- **1-pdepend-analyzer.py**: Analyzes PDépend XML output for code complexity metrics (Sections 5.1 and 5.2)
- **2-sonarqube-analyzer.py**: Analyzes SonarQube API data for quality issues and security hotspots (Sections 5.3 and 5.5)

The scripts process PHP codebase metrics and generate CSV reports with publication-quality visualizations (PNG figures).

## Development Environment

### Setup

```bash
# Virtual environment is located in .venv/
source .venv/bin/activate  # Activate venv

# Install dependencies
pip install -r requirements.txt
```

Dependencies: pandas, numpy, requests, scipy, matplotlib, seaborn

### Running the Analyzers

**PDépend Analyzer (Complexity)**

```bash
python 1-pdepend-analyzer.py [pdepend-summary.xml]
# Default input: pdepend-summary.xml
# Output directory: ./output_pdepend/
```

**SonarQube Analyzer (Quality Issues)**

```bash
python 2-sonarqube-analyzer.py
# Configuration is hardcoded in main() function
# Output directory: ./output_sonarqube/
```

## Code Architecture

### 1-pdepend-analyzer.py (PdependAnalyzer class)

**Data Flow:**

1. `parse_pdepend_xml()` - Parses PDépend summary.xml → 3 dataframes (files, classes, methods)
2. `generate_descriptive_stats()` - Aggregate statistics (LOC, WMC, CCN averages)
3. `generate_complexity_analysis()` - File-level complexity merging class/method metrics
4. `create_visualizations()` - Generates 4 figures (box plots, bar charts, histograms, scatter plots)

**Key Filters:**

- Only analyzes classes in `application/controller` paths (line 67-68)
- Only analyzes `+global` package (line 60-61)

**Metrics Tracked:**

- Files: LOC, NCLOC, LLOC, CLOC
- Classes: CCN, CCN2, WMC, NOM, NOC, CA, CE, CBO, DIT
- Methods: CCN, LOC, NPath

**Complexity Thresholds:**

- WMC > 100: High complexity threshold (figure_5_2)
- Method CCN > 10: High complexity (figure_5_3, orange)
- Method CCN > 30: Critical complexity (figure_5_3, red; CSV output)

### 2-sonarqube-analyzer.py (SonarQubeAnalyzer class)

**Data Flow:**

1. `fetch_file_issues()` - Fetches issues from SonarQube API → file_issues_df
2. `fetch_hotspot_categories()` - Fetches security hotspot facets → hotspot_categories_df
3. `generate_quality_issues_analysis()` - Aggregates issues by quality/severity
4. `create_quality_issues_visualizations()` - Generates 3 figures (stacked bars, pie charts)
5. `create_security_hotspot_visualizations()` - Generates 1 figure (hotspot categories)

**SonarQube API Integration:**

- Uses `/api/issues/search` for file issues (paginated, 500 per page)
- Uses `/api/hotspots/search` with facets for category distribution
- Uses `/api/measures/component_tree` to discover all project files
- Supports both MQR mode (impacts) and Standard mode (type/severity) - lines 90-122
- Token authentication via HTTP Basic Auth

**Issue Classification:**

- 3 quality aspects: Security, Reliability, Maintainability
- 5 severity levels: Blocker, High, Medium, Low, Info
- 15 issue counters per file (quality × severity matrix)

**Configuration (hardcoded in main()):**

- `sonar_host`: SonarQube server URL
- `project_key`: Project identifier
- `token`: SonarQube authentication token (plaintext in code - line 596)
- `file_paths`: Optional specific files list (empty = scan all)

## Output Structure

**PDépend Outputs (output_pdepend/):**

- CSV: `section_5_1_descriptive_statistics.csv`, `section_5_2_complexity_data.csv`, `section_5_2_complexity_distribution.csv`, `section_5_2_top10_complex_files.csv`, `section_5_2_complex_methods_ccn30.csv`
- Figures: `figure_5_1_complexity_distribution.png` (box plots), `figure_5_2_top10_complex_files.png` (horizontal bars), `figure_5_3_method_complexity_histogram.png` (histogram with thresholds), `figure_5_4_wmc_vs_ncloc.png` (scatter with annotations)

**SonarQube Outputs (output_sonarqube/):**

- CSV: `section_5_3_file_issues.csv`, `section_5_3_overall_summary.csv`, `section_5_3_issues_by_severity.csv`, `section_5_3_top20_problematic_files.csv`, `section_5_5_hotspot_categories.csv`
- Figures: `figure_5_5_issues_by_quality_severity.png` (grouped bars), `figure_5_6_top10_files_issues.png` (stacked horizontal bars), `figure_5_7_issue_distribution.png` (dual pie charts), `figure_5_8_hotspot_categories.png` (bar + pie combo, if hotspots exist)

## Important Implementation Details

**Visualization Style:**

- Uses `seaborn-v0_8-paper` style for publication quality
- 300 DPI PNG output with tight bounding boxes
- Consistent color schemes: Security=red, Reliability=blue, Maintainability=green

**Data Merging (PDépend):**

- Line 157: Merges file metrics with aggregated class metrics (groupby file)
- Line 166: Merges method statistics (mean/max/sum CCN per file)
- Handles missing data with fillna(0)

**API Pagination & Rate Limiting (SonarQube):**

- Max 10 pages per file issues query (line 125)
- Max 20 pages for file discovery (line 182)
- 0.5s sleep every 50 files (line 141-142)

**Data Processing:**

- File paths in visualizations use `Path(f).name` for clean display (removes directory paths)
- Issues dataframes use lowercase keys for consistent mapping
- Methods with CCN=0 filtered from histograms (line 314)
